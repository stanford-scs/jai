// -*-C++-*-

#pragma once

#include "config.h"
#include "cred.h"
#include "err.h"
#include "fs.h"
#include "options.h"

#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

extern "C" char **environ;

inline const char *env_or_empty(std::string_view var) {
  const char *p = getenv(std::string(var).c_str());
  return p ? p : "";
}

// Calls exp("VAR"sv) to expand strings like "123${VAR}456".
template <typename Exp = decltype(env_or_empty)>
std::string var_expand(std::string_view in, Exp &&exp = env_or_empty)
  requires requires(std::string r) { r += exp(in); }
{
  std::string ret;
  for (std::size_t i = 0, e = in.size(); i < e;)
    if (in[i] == '\\')
      ret += (++i < e ? in[i++] : '\\');
    else if (size_t j;
             in.substr(i, 2) == "${" && (j = in.find('}', i + 2)) != in.npos) {
      ret += exp(in.substr(i + 2, j - i - 2));
      i = j + 1;
    } else
      ret += in[i++];
  return ret;
}

inline pid_t xfork(std::uint64_t flags = 0) {
  clone_args ca{.flags = flags, .exit_signal = SIGCHLD};
  if (auto ret = syscall(SYS_clone3, &ca, sizeof(ca)); ret != -1)
    return ret;
  syserr("clone3");
}

inline sigset_t sigsingleton(int sig) {
  sigset_t ret;
  sigemptyset(&ret);
  sigaddset(&ret, sig);
  return ret;
}

#define xsetns(fd, type)                                                       \
  do {                                                                         \
    if (setns(fd, type)) {                                                     \
      warn("setns({}, {}): {}", fdpath(fd), #type, strerror(errno));           \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

constexpr const char *kUntrustedUser = UNTRUSTED_USER;
constexpr const char *kUntrustedGecos = "JAI sandbox untrusted user";
constexpr const char *kRunRoot = "/run/jai";

extern const std::string jai_defaults;
extern const std::string default_conf;
extern const std::string default_jail;

struct Config {
  enum Mode { kCasual, kBare, kStrict };

  Mode mode_{kStrict};
  PathSet grant_directories_;
  bool grant_cwd_{true};
  std::set<std::string, std::less<>> env_filter_;
  std::map<std::string, std::string, std::less<>> setenv_;
  path cwd_;
  std::string shellcmd_;
  PathSet mask_files_;
  bool mask_warn_{};
  bool parsing_config_file_{};

  std::string user_;
  path homepath_;
  path homejaipath_;
  path storagedir_;
  path sandbox_name_;
  Credentials user_cred_;
  Credentials untrusted_cred_;
  path shell_;
  mode_t old_umask_ = 0755;

  Fd home_fd_;
  Fd home_jai_fd_;
  Fd storage_fd_;
  Fd run_jai_fd_;
  Fd run_jai_user_fd_;

  // Hold some file descriptors to prevent unmounting
  std::vector<Fd> mp_holder_;

  PathSet config_loop_detect_;

  void init_credentials();
  Fd make_idmap_ns();
  Fd make_mnt_ns();
  void exec(int nsfd, char **argv);
  void unmount();
  bool unmountall();
  std::unique_ptr<Options> opt_parser(bool dotjail = false);

  int complete(Options::Completions c);
  void parse_config_fd(int fd, Options *opts = nullptr);
  bool parse_config_file(path file, Options *opts = nullptr);
  std::vector<const char *> make_env();

  static void fix_proc();
  [[noreturn]] static void parent_loop(pid_t jai_init_pid, int stop_requests);
  void static pid1(Fd stop_me);
  [[noreturn]] void pid2(char **argv);

  [[nodiscard]] static Defer asuser(const Credentials *crp);
  [[nodiscard]] Defer asuser() { return asuser(&user_cred_); }
  void check_user(const struct stat &sb, std::string path_for_error = {},
                  bool untrusted_ok = false);
  void check_user(int fd, std::string path_for_error = {},
                  bool untrusted_ok = false) {
    check_user(xfstat(fd), path_for_error.empty() ? fdpath(fd) : path_for_error,
               untrusted_ok);
  }
  Fd ensure_udir(int dfd, const path &p, mode_t perm = 0700,
                 FollowLinks follow = kFollow) {
    auto _restore = asuser();
    Fd fd = ensure_dir(dfd, p, perm, follow);
    check_user(*fd);
    return fd;
  }

  int home();
  int home_jai(bool create = false);
  int storage();
  int run_jai();
  int run_jai_user();
  const path &cwd() {
    if (cwd_.empty()) {
      auto restore = asuser();
      cwd_ = canonical(std::filesystem::current_path());
    }
    return cwd_;
  }

  Fd make_blacklist(int dfd, path name);
  Fd make_home_overlay();
  Fd make_private_tmp();
  Fd make_private_run();
  Fd make_private_passwd();

  const char *env_lookup(std::string_view var) {
    if (auto it = setenv_.find(var); it != setenv_.end())
      if (auto pos = it->second.find('='); pos != it->second.npos)
        return it->second.c_str() + pos + 1;
    return env_or_empty(var);
  }
  std::string expand(std::string_view in) {
    return parsing_config_file_
               ? var_expand(
                     in, [this](std::string_view v) { return env_lookup(v); })
               : std::string(in);
  }

  static bool name_ok(path p) {
    return p.is_relative() && std::ranges::distance(p.begin(), p.end()) == 1 &&
           *p.c_str() != '.';
  }
  void mask_warn() {
    if (mask_warn_) {
      warn(R"(--mask ignored because {5}/{0}/{1}.home already mounted.
{2:>{3}}  Run "{4} -u" to unmount overlays.)",
           user_, sandbox_name_.string(), "", prog.filename().string().size(),
           prog.filename().string(), kRunRoot);
      mask_warn_ = false;
    }
  }
};

template <> struct std::formatter<Config::Mode> : std::formatter<const char *> {
  using super = std::formatter<const char *>;
  auto format(Config::Mode m, auto &&ctx) const {
    using enum Config::Mode;
    switch (m) {
    case kStrict:
      return super::format("strict", ctx);
    case kBare:
      return super::format("bare", ctx);
    case kCasual:
      return super::format("casual", ctx);
    default:
      err<std::logic_error>("Config::Mode with bad value {}", int(m));
    }
  }
};
