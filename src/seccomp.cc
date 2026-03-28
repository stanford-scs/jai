#include "seccomp.h"
#include "err.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

// Architecture validation constant
#if defined(__x86_64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
#else
#error "Unsupported architecture for seccomp filter"
#endif

// Syscalls to deny.  Returns EPERM so programs get a clean error.
//
// This is a targeted denylist rather than a full allowlist — an
// allowlist would break too many programs.  These are syscalls that
// have no legitimate use inside a user-facing sandbox.
static constexpr int denied_syscalls[] = {
    // Kernel module loading (ring 0 code execution)
    SYS_init_module,
    SYS_finit_module,
    SYS_delete_module,

    // kexec (replace running kernel)
    SYS_kexec_load,
    SYS_kexec_file_load,

    // Reboot / power
    SYS_reboot,

#ifdef SYS_iopl
    // Raw I/O port access (x86 only)
    SYS_iopl,
    SYS_ioperm,
#endif

    // Swap management
    SYS_swapon,
    SYS_swapoff,

    // System clock manipulation (system-wide)
    SYS_settimeofday,
    SYS_clock_settime,
    SYS_adjtimex,
    SYS_clock_adjtime,

    // Mount operations (defense in depth, namespace already restricts)
    SYS_mount,
    SYS_umount2,
    SYS_pivot_root,

    // Namespace creation (prevent further escalation)
    SYS_unshare,

    // Keyring operations
    SYS_add_key,
    SYS_request_key,
    SYS_keyctl,

    // BPF program loading (prevent sandbox escape via eBPF)
    SYS_bpf,

    // Exploitation primitives
    SYS_userfaultfd,
    SYS_perf_event_open,

    // ptrace (prevent debugging/injecting other processes)
    SYS_ptrace,

    // Accounting / quota
    SYS_acct,
    SYS_quotactl,

    // open_by_handle_at can bypass mount namespace restrictions
    SYS_open_by_handle_at,
};

void
install_seccomp_filter()
{
  const auto n = std::size(denied_syscalls);

  // Build BPF program:
  //   [0]   load arch
  //   [1]   check arch (kill if wrong)
  //   [2]   kill (wrong arch)
  //   [3]   load syscall number
  //   [4..4+n-1]  check each denied syscall
  //   [4+n]       ALLOW
  //   [4+n+1]     ERRNO(EPERM)
  std::vector<struct sock_filter> filter;
  filter.reserve(4 + n + 2);

  // Load and validate architecture
  filter.push_back({BPF_LD | BPF_W | BPF_ABS, 0, 0,
                    (uint32_t)offsetof(struct seccomp_data, arch)});
  filter.push_back({BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_CURRENT});
  filter.push_back({BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS});

  // Load syscall number
  filter.push_back({BPF_LD | BPF_W | BPF_ABS, 0, 0,
                    (uint32_t)offsetof(struct seccomp_data, nr)});

  // For each denied syscall: jump to DENY if match, fall through if not.
  // Jump offset to DENY = (remaining checks) + 1 (skip ALLOW)
  for (size_t i = 0; i < n; ++i) {
    uint8_t jt = n - i;  // jump over remaining checks + ALLOW
    filter.push_back(
        {BPF_JMP | BPF_JEQ | BPF_K, jt, 0, (uint32_t)denied_syscalls[i]});
  }

  // Default: allow
  filter.push_back({BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW});

  // Denied: return EPERM
  filter.push_back({BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM});

  struct sock_fprog prog = {
      .len = (unsigned short)filter.size(),
      .filter = filter.data(),
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    syserr("prctl(PR_SET_NO_NEW_PRIVS)");

  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog))
    syserr("seccomp(SECCOMP_SET_MODE_FILTER)");
}
