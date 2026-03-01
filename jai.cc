#include "jai.h"

#include <cassert>
#include <cstring>
#include <print>

#include <acl/libacl.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/futex.h>
#include <pwd.h>
#include <sched.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

path prog;

constexpr const char *kRunRoot = "/run/jai";
constexpr const char *kSB = "sandboxed-home";

struct Config {
  std::string user_;
  uid_t uid_ = -1;
  gid_t gid_ = -1;
  path homepath_;

  Fd home_fd_;
  Fd home_jai_fd_;
  Fd run_jai_fd_;
  Fd run_jai_user_fd_;

  void init();
  void reset()
  {
    home_fd_.reset();
    home_jai_fd_.reset();
    run_jai_fd_.reset();
    run_jai_user_fd_.reset();
  }

  Fd make_ns();
  int make_ns_child();

  void unmount();

  [[nodiscard]] Defer asuser();
  void check_user(int fd);

  int home();
  int home_jai();
  int run_jai();
  int run_jai_user();

  Fd make_blacklist(int dfd, path name);
  Fd make_home_overlay();
  Fd make_private_tmp();
};

static std::expected<Fd, Defer>
lock_or_validate_file(int dfd, const path &file, int flags, auto &&validate)
    requires requires {
      { validate(1) } -> std::convertible_to<bool>;
    }
{
  assert(!file.empty());
  path lockfile = cat(file, ".lock");
  flags |= O_NOFOLLOW | O_CLOEXEC;

  return lock_or_validate(dfd, lockfile, [&] -> Fd {
    if (Fd fd = openat(dfd, file.c_str(), flags); fd && validate(*fd))
      return fd;
    else if (!fd && errno != ENOENT)
      syserr(R"(openat("{}", "{}", {}))", fdpath(dfd), file.string(),
             open_flags_to_string(flags));
    return {};
  });
}

void
Config::init()
{
  char buf[512];
  struct passwd pwbuf, *pw{};

  auto realuid = getuid();

  const char *envuser = user_.empty() ? getenv("SUDO_USER") : user_.c_str();
  if (realuid == 0 && envuser) {
    if (getpwnam_r(envuser, &pwbuf, buf, sizeof(buf), &pw))
      err("cannot find password entry for user {}", envuser);
  }
  else if (getpwuid_r(realuid, &pwbuf, buf, sizeof(buf), &pw))
    err("cannot find password entry for uid {}", uid_);

  user_ = pw->pw_name;
  uid_ = pw->pw_uid;
  gid_ = pw->pw_gid;
  homepath_ = pw->pw_dir;

  // Paranoia about ptrace, because we will drop privileges to access
  // the file system as the user.
  prctl(PR_SET_DUMPABLE, 0);

  // Set all user permissions except user ID so we can easily drop
  // privileges in asuser.
  if (realuid == 0 && uid_ != 0) {
    if (initgroups(user_.c_str(), gid_))
      syserr("initgroups");
    if (setgid(gid_))
      syserr("setgid");
  }
}

Defer
Config::asuser()
{
  if (!uid_ || geteuid())
    // If target is root or already dropped privileges, do nothing
    return {};
  if (seteuid(uid_))
    syserr("seteuid");
  return Defer{[] { seteuid(0); }};
}

void
Config::check_user(int fd)
{
  if (auto sb = xfstat(fd); sb.st_uid != uid_)
    err("{}: owned by {} should be owned by {}", fdpath(fd), sb.st_uid, uid_);
}

int
Config::home_jai()
{
  if (!home_jai_fd_) {
    auto restore = asuser();
    home_jai_fd_ = ensure_dir(home(), ".jai", 0700, kFollow);
    check_user(*home_jai_fd_);
  }
  return *home_jai_fd_;
}

int
Config::run_jai()
{
  if (run_jai_fd_)
    return *run_jai_fd_;

  auto r = lock_or_validate_file(-1, kRunRoot, O_RDONLY, [](int fd) {
    return is_mountpoint(fd) && (xfstat(fd).st_mode & 0777);
  });
  if (r)
    return *(run_jai_fd_ = std::move(*r));

  // Get rid of any partially set up directories
  recursive_umount(kRunRoot);

  xmnt_move(*make_tmpfs("size", "64M", "mode", "0", "gid", "0"),
            *ensure_dir(-1, kRunRoot, 0755, kFollow));

  Fd dirfd = xopenat(-1, kRunRoot, O_RDONLY | O_DIRECTORY);
  xmnt_propagate(*dirfd, MS_PRIVATE);
  fchmod(*dirfd, 0755);
  return *(run_jai_fd_ = std::move(dirfd));
}

int
Config::run_jai_user()
{
  if (run_jai_user_fd_)
    return *run_jai_user_fd_;

  Fd dirfd = ensure_dir(run_jai(), user_, 0750, kNoFollow);
  RaiiHelper<acl_free, acl_t> acl = acl_get_fd(*dirfd);
  if (!acl)
    syserr("acl_get_fd");
  if (int r = acl_equiv_mode(acl, nullptr); r < 0)
    syserr("acl_equiv_mode");
  else if (r == 0) {
    auto text = std::format("u::rwx,g::---,o::---,u:{}:r-x,m::r-x", uid_);
    set_fd_acl(*dirfd, text.c_str(), kAclAccess);
  }
  return *(run_jai_user_fd_ = std::move(dirfd));
}

int
Config::home()
{
  if (!home_fd_) {
    auto cleanup = asuser();
    Fd fd;
    if (!(fd = open(homepath_.c_str(), O_PATH | O_CLOEXEC)))
      syserr("{}", homepath_.string());
    check_user(*fd);
    home_fd_ = std::move(fd);
  }
  return *home_fd_;
}

std::vector default_blacklist = {
    ".jai",
    ".ssh",
    ".gnupg",
    ".local/share/keyrings",
    ".netrc",
    ".git-credentials",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".config/gh",
    ".config/Keybase",
    ".config/kube",
    ".docker",
    ".password-store",
    ".mozilla",
    ".config/chromium",
    ".config/google-chrome",
    ".config/BraveSoftware",
    ".bash_history",
    ".zsh_history",
};

Fd
Config::make_blacklist(int dfd, path name)
{
  Fd blacklistfd = ensure_dir(dfd, name.c_str(), 0700, kFollow);
  check_user(*blacklistfd);
  if (!is_dir_empty(*blacklistfd))
    return blacklistfd;

  for (path p : default_blacklist) {
    try {
      auto subdir = p.relative_path().parent_path();
      xopenat(subdir.empty()
                  ? *blacklistfd
                  : *ensure_dir(*blacklistfd, subdir, 0700, kNoFollow),
              p.filename(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    } catch (const std::exception &e) {
      std::println(stderr, "{}", e.what());
    }
  }

  return blacklistfd;
}

Fd
Config::make_home_overlay()
{
  Fd sandboxed_home = ensure_dir(run_jai_user(), kSB, 0755, kFollow, true);
  if (is_mountpoint(*sandboxed_home))
    return sandboxed_home;

  auto restore = asuser();
  Fd changes = make_blacklist(home_jai(), "changes");
  Fd work = ensure_dir(home_jai(), "work", 0700, kFollow);
  check_user(*work);
  restore.reset();

  Fd fsfd = fsopen("overlay", FSOPEN_CLOEXEC);
  if (!fsfd)
    syserr(R"(fsopen("overlay"))");
  if (fsconfig(*fsfd, FSCONFIG_SET_FD, "lowerdir+", nullptr, home()) ||
      fsconfig(*fsfd, FSCONFIG_SET_FD, "upperdir", nullptr, *changes) ||
      fsconfig(*fsfd, FSCONFIG_SET_FD, "workdir", nullptr, *work))
    syserr("fsconfig(FSCONFIG_SET_FD)");
  Fd mnt = make_mount(*fsfd);

  xmnt_move(*mnt, *sandboxed_home);
  restore = asuser();
  return xopenat(run_jai_user(), kSB, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
}

Fd
Config::make_private_tmp()
{
  Fd tmp = ensure_dir(run_jai_user(), "tmp", 0755, kFollow);
  if (is_mountpoint(*tmp))
    return tmp;
  xmnt_move(*make_tmpfs("gid", "0", "mode", "01777", "size", "40%"), *tmp);
  return xopenat(run_jai_user(), "tmp", O_RDONLY | O_NOFOLLOW);
}

Fd
Config::make_ns()
{
  auto r = lock_or_validate_file(run_jai_user(), "ns", O_RDWR,
                                 [](int fd) { return is_mountpoint(fd); });
  if (r)
    return std::move(*r);

  make_home_overlay();
  make_private_tmp();

  int pid = -1;
  auto stack = std::make_unique<std::array<char, 0x10'0000>>();
  Defer reap([&pid] {
    if (pid > 0)
      while (waitpid(pid, nullptr, 0) == -1 && errno == EINTR)
        ;
  });

  Fd pipefds[2];
  if (int fds[2]; pipe(fds))
    syserr("pipe");
  else
    std::ranges::copy(fds, pipefds);

  struct CS {
    Fd *pipefds;
    Config *c;
  } child_state = {pipefds, this};

  pid = clone(
      +[](void *_cs) -> int {
        auto cs = static_cast<CS *>(_cs);
        cs->pipefds[1].reset();
        int r = 1;
        try {
          r = cs->c->make_ns_child();
          char c;
          read(*cs->pipefds[0], &c, 1);
        } catch (const std::exception &e) {
          std::println(stderr, "{}", e.what());
          fflush(stderr);
        }
        return r;
      },
      stack->data() + stack->size(), CLONE_NEWNS | SIGCHLD, &child_state);

  pipefds[0].reset();
  Fd nsmnt =
      clone_tree(*xopenat(-1, std::format("/proc/{}/ns/mnt", pid), O_RDONLY));
  xmnt_propagate(*nsmnt, MS_PRIVATE);
  pipefds[1].reset();
  reap.release();
  int status;
  while (waitpid(pid, &status, 0) && errno == EINTR)
    ;
  if (status)
    err("failed to create new namespace");
  Fd ns = xopenat(run_jai_user(), "ns", O_CREAT | O_RDWR, 0600);
  xmnt_move(*nsmnt, *ns);
  return nsmnt;
}

int
Config::make_ns_child()
{
  reset();
  const path mnt = "/mnt";
  const path mrj = mnt / path{kRunRoot}.relative_path();
  auto oldroot = xopenat(-1, "/", O_PATH);
  xmnt_propagate(*oldroot, MS_SLAVE, true);
  Fd newroot = clone_tree(*oldroot, {}, true);
  xmnt_setattr(*newroot,
               mount_attr{
                   .attr_set = MOUNT_ATTR_RDONLY,
                   .propagation = MS_PRIVATE,
               },
               AT_RECURSIVE);
  xmnt_move(*newroot, -1, mnt);
  umount2(mrj.c_str(), MNT_DETACH);
  xmnt_move(-1, kRunRoot, -1, mrj.c_str(), 0);

  if (chdir(mnt.c_str()))
    syserr(R"(chdir("{}"))", mnt.string());
  if (syscall(SYS_pivot_root, ".", "."))
    syserr("pivot_root");
  if (umount2(".", MNT_DETACH))
    syserr("umount2 root after pivot");
  if (chdir("/"))
    syserr(R"(chdir("/"))");

  umount2("/tmp", MNT_DETACH);     // ignore errors
  umount2("/var/tmp", MNT_DETACH); // ignore errors

  auto tmp = xopenat(run_jai_user(), "tmp", O_DIRECTORY | O_PATH | O_NOFOLLOW);
  xmnt_move(*clone_tree(*tmp), -1, "/tmp");
  xmnt_move(*clone_tree(*tmp), -1, "/var/tmp");
  tmp.reset();

  Fd newhome = xopenat(-1, homepath_.c_str(), O_RDONLY | O_NOFOLLOW);
  check_user(*newhome);
  auto sandboxed_home =
      xopenat(run_jai_user(), kSB, O_RDONLY | O_NOFOLLOW | O_DIRECTORY);
  xmnt_move(*clone_tree(*sandboxed_home), *newhome);

  if (umount2(kRunRoot, MNT_DETACH))
    syserr(R"(umount2("{}"))", kRunRoot);

  return 0;
}

void
Config::unmount()
{
  Fd lock;
  while (!(lock = open_lockfile(run_jai_user(), "ns.lock")))
    ;
  recursive_umount(path(kRunRoot) / user_);
  unlinkat(run_jai_user(), "tmp", AT_REMOVEDIR);
  unlinkat(run_jai_user(), kSB, AT_REMOVEDIR);
  unlinkat(run_jai_user(), "ns", 0);
  unlinkat(run_jai_user(), "ns.lock", 0);
  lock.reset();
  unlinkat(run_jai(), user_.c_str(), AT_REMOVEDIR);
}

[[noreturn]] static void
usage(int status)
{
  std::println(status ? stderr : stdout, R"(usage:
   {0}                            create sandboxed-home under {1}
   {0} -u                         unmount sandboxed-home
   {0} cmd [arg...]               run cmd with access to cwd
   {0} -d dir [-d dir...] cmd...  run cmd with access to specified dirs)",
               prog.filename().string(), kRunRoot);
  exit(status);
}

int
main(int argc, char **argv)
{
  umask(022);
  if (argc > 0)
    prog = argv[0];
  else
    prog = "jai";

  bool opt_u{};
  std::vector<path> opt_d;

  int opt;
  while ((opt = getopt(argc, argv, "+d:uh")) != -1)
    switch (opt) {
    case 'd':
      opt_d.push_back(optarg);
      break;
    case 'u':
      opt_u = true;
      break;
    case 'h':
      usage(0);
    default:
      usage(2);
    }

  std::vector<char *> cmd(argv + optind, argv + argc);
  if (opt_u && (!opt_d.empty() || !cmd.empty()))
    usage(2);

  auto go = [&] {
    Config conf;
    conf.init();

    if (opt_u) {
      conf.unmount();
      exit(0);
    }

    auto fd = conf.make_ns();
  };

#if 1
  go();                         // make exceptions crash
#else
  try {
    go();
  } catch (const std::exception &e) {
    std::println(stderr, "{}: {}", prog.filename().string(), e.what());
    return 1;
  }
#endif
  return 0;
}
