#include "jai.h"

#include <cassert>
#include <cstring>
#include <filesystem>
#include <print>

#include <acl/libacl.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/futex.h>
#include <pwd.h>
#include <sched.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

path prog;

constexpr const char *kRunRoot = "/run/jai";
constexpr const char *kSB = "sandboxed-home";

#define xsetns(fd, type)                                                       \
  do {                                                                         \
    if (setns(fd, type)) {                                                     \
      std::println(stderr, "setns({}, {})", fdpath(fd), #type);                \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

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
  Fd make_ns(const std::vector<path> &);
  void run(int nsfd, const path &cwd, char **argv);
  void unmount();

  [[nodiscard]] Defer asuser();
  void check_user(int fd, std::string path_for_error = {});

  int home();
  int home_jai();
  int run_jai();
  int run_jai_user();

  Fd make_blacklist(int dfd, path name);
  Fd make_home_overlay();
  Fd make_private_tmp();
};

static std::expected<Fd, Defer>
lock_or_validate_file(int dfd, const path &file, int flags, auto &&validate,
                      path lockfile = {}) requires requires {
  { validate(1) } -> std::convertible_to<bool>;
}
{
  assert(!file.empty());
  if (lockfile.empty())
    lockfile = cat(file, ".lock");
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
  std::vector<char> buf;
  struct passwd pwbuf, *pw{};

  auto realuid = getuid();

  const char *envuser{};
  if (!user_.empty())
    envuser = user_.c_str();
  else if (const char *u = getenv("SUDO_USER"))
    envuser = u;
  else if (const char *u = getenv("USER"))
    envuser = u;

  for (;;) {
    buf.resize(std::max(128uz, 2 * buf.size()));
    if (realuid == 0 && envuser) {
      if (int r = getpwnam_r(envuser, &pwbuf, buf.data(), buf.size(), &pw); pw)
        break;
      else if (r != ERANGE)
        err("cannot find password entry for user {}", envuser);
    }
    else if (int r = getpwuid_r(realuid, &pwbuf, buf.data(), buf.size(), &pw);
             pw)
      break;
    else if (r != ERANGE)
      err("cannot find password entry for uid {}", uid_);
  }

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
Config::check_user(int fd, std::string p)
{
  if (auto sb = xfstat(fd); sb.st_uid != uid_)
    err("{}: owned by {} should be owned by {}", p.empty() ? fdpath(fd) : p,
        sb.st_uid, uid_);
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

  auto r =
      lock_or_validate_file(-1, kRunRoot, O_RDONLY | O_DIRECTORY, [](int fd) {
        return is_mountpoint(fd) && (xfstat(fd).st_mode & 0777);
      });
  if (r)
    return *(run_jai_fd_ = std::move(*r));

  // Get rid of any partially set up directories
  recursive_umount(kRunRoot);

  xmnt_move(*make_tmpfs("run-jai", "size", "64M", "mode", "0", "gid", "0"),
            *ensure_dir(-1, kRunRoot, 0755, kFollow));

  Fd dirfd = xopenat(-1, kRunRoot, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
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

const auto default_blacklist = std::to_array<const char *>({
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
});

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
  auto r = lock_or_validate_file(
      run_jai_user(), "home", O_RDONLY | O_DIRECTORY,
      [](int fd) { return is_mountpoint(fd); }, ".lock");
  if (r)
    return std::move(*r);

  Fd sandboxed_home = ensure_dir(run_jai_user(), kSB, 0755, kFollow, true);
  if (is_mountpoint(*sandboxed_home))
    return sandboxed_home;

  auto restore = asuser();
  Fd changes = make_blacklist(home_jai(), "changes");
  Fd work = ensure_dir(home_jai(), "work", 0700, kFollow);
  check_user(*work);
  restore.reset();

  Fd fsfd = xfsopen("overlay", "jai-home");
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
  auto r = lock_or_validate_file(
      run_jai_user(), "tmp", O_RDONLY | O_DIRECTORY,
      [](int fd) { return is_mountpoint(fd); }, ".lock");
  if (r)
    return std::move(*r);

  Fd tmp = ensure_dir(run_jai_user(), "tmp", 0755, kFollow);
  if (is_mountpoint(*tmp))
    return tmp;
  xmnt_move(*make_tmpfs("jai-tmp", "gid", "0", "mode", "01777", "size", "40%"),
            *tmp);
  return xopenat(run_jai_user(), "tmp", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
}

Fd
Config::make_ns(const std::vector<path> &dirs)
{
  Fd oldns = xopenat(-1, "/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  Defer restore{[fd = *oldns] { xsetns(fd, CLONE_NEWNS); }};

  const mount_attr attr{
      .attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
      .propagation = MS_PRIVATE,
  };
  Fd tmp = clone_tree(*make_private_tmp());
  xmnt_setattr(*tmp, attr);
  Fd home = clone_tree(*make_home_overlay());
  xmnt_setattr(*home, attr);

  if (unshare(CLONE_NEWNS))
    syserr("unshare(CLONE_NEWNS)");
  Fd newns = xopenat(-1, "/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  xmnt_setattr(-1, "/",
               mount_attr{
                   .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID,
                   .propagation = MS_PRIVATE,
               });

  if (umount2(kRunRoot, MNT_DETACH))
    syserr("umount2({}, MNT_DETACH)", kRunRoot);
  umount2("/tmp", MNT_DETACH);     // ignore error
  umount2("/var/tmp", MNT_DETACH); // ignore error
  xmnt_move(*tmp, -1, "/tmp");
  xmnt_move(*clone_tree(-1, "/tmp"), -1, "/var/tmp", 0);
  xmnt_move(*home, -1, homepath_);

  for (auto d : dirs) {
    if (d.is_relative())
      d = "/" / d;
    xsetns(*oldns, CLONE_NEWNS);
    Fd src = clone_tree(*xopenat(-1, d, O_DIRECTORY | O_PATH | O_CLOEXEC));
    check_user(*src, d);
    xmnt_setattr(*src, attr);
    xsetns(*newns, CLONE_NEWNS);
    Fd dst = xopenat(-1, d, O_DIRECTORY | O_PATH | O_CLOEXEC);
    check_user(*dst, d);
    xmnt_move(*src, *dst);
  }

  return newns;
}

void
Config::unmount()
{
  Fd lock;
  while (!(lock = open_lockfile(run_jai_user(), ".lock")))
    ;
  recursive_umount(path(kRunRoot) / user_);
  unlinkat(run_jai_user(), "tmp", AT_REMOVEDIR);
  unlinkat(run_jai_user(), kSB, AT_REMOVEDIR);
  unlinkat(run_jai_user(), "ns", 0);
  unlinkat(run_jai_user(), ".lock", 0);
  lock.reset();
  unlinkat(run_jai(), user_.c_str(), AT_REMOVEDIR);
}

auto env_blacklist = std::to_array<const char *>({
    // Azure
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    // Databases (connection URIs contain embedded credentials)
    "DATABASE_URL",
    "MONGO_URI",
    "MONGODB_URI",
    "REDIS_URL",
    // GCP
    "GOOGLE_APPLICATION_CREDENTIALS",
    // Docker / K8s
    "KUBECONFIG",
    // Bitbucket
    "BB_AUTH_STRING",
    // Sentry
    "SENTRY_DSN",
    // Slack
    "SLACK_WEBHOOK_URL",
});

auto env_suffix_blacklist = std::to_array<const char *>({
    "_ACCESS_KEY", "_API_KEY",     "_APIKEY",
    "_AUTH",       "_AUTH_TOKEN",  "_CONNECTION_STRING",
    "_CREDENTIAL", "_CREDENTIALS", "_PASSWD",
    "_PASSWORD",   "_PID",         "_PRIVATE_KEY",
    "_PWD",        "_SECRET",      "_SECRET_KEY",
    "_SOCK",       "_SOCKET",      "_SOCKET_PATH",
    "_TOKEN",
});

extern "C" char **environ;

void
sanitize_env()
{
  for (const char *v : env_blacklist)
    unsetenv(v);

  std::vector<std::string> to_remove;
  for (char **v = environ; *v; ++v) {
    std::string_view sv(*v);
    if (auto eq = sv.find('='); eq != sv.npos)
      sv = sv.substr(0, eq);
    for (std::string_view s : env_suffix_blacklist)
      if (sv.ends_with(s)) {
        to_remove.push_back(std::string{sv});
        break;
      }
  }
  for (const auto &v : to_remove)
    unsetenv(v.c_str());
}

void
Config::run(int nsfd, const path &cwd, char **argv)
{
  xsetns(nsfd, CLONE_NEWNS);
  if (unshare(CLONE_NEWPID | CLONE_NEWIPC))
    syserr("unshare(CLONE_NEWPID)");

  if (auto pid = fork(); pid < 0)
    syserr("fork");
  else if (pid != 0) {
    close(nsfd);
    int status;
    while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
      ;
    if (WIFEXITED(status))
      exit(WEXITSTATUS(status));
    if (WIFSIGNALED(status)) {
      signal(WTERMSIG(status), SIG_DFL);
      raise(WTERMSIG(status));
    }
    _exit(1);
  }

  try {
    recursive_umount("/proc");
    Fd conf = xfsopen("proc", "proc");
    if (!conf)
      syserr(R"(fsopen("proc"))");
    xmnt_move(*make_mount(*conf, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
                                     MOUNT_ATTR_NOEXEC),
              -1, "/proc");
  } catch (const std::exception &e) {
    std::println(stderr, "{}: {}", prog.filename().string(), e.what());
    _exit(1);
  }

  if (setuid(uid_))
    syserr("setuid");
  if (chdir(cwd.c_str()))
    syserr("chdir({})", cwd.string());
  sanitize_env();
  execvp(argv[0], argv);
  perror(argv[0]);
  _exit(1);
}

[[noreturn]] static void
usage(int status)
{
  std::println(status ? stderr : stdout,
               R"(usage: {0} [-u | [-D | -d dir ...] cmd [arg...]]
   no arguments  create sandboxed-home under {1}
   -u            unmount sandboxed-home
   -d dir        provide unrestricted access to dir in addition to $PWD
   -D            don't provide unrestricted access to $PWD)",
               prog.filename().string(), kRunRoot);
  exit(status);
}

void
do_main(int argc, char **argv)
{
  Config conf;
  conf.init();
  auto restore = conf.asuser();

  bool opt_u{}, opt_D{};
  std::vector<path> opt_d;
  path cwd = canonical(std::filesystem::current_path());

  int opt;
  while ((opt = getopt(argc, argv, "+d:Duh")) != -1)
    switch (opt) {
    case 'd':
      opt_d.emplace_back(canonical(path(optarg)));
      break;
    case 'u':
      opt_u = true;
      break;
    case 'D':
      opt_D = true;
      break;
    case 'h':
      usage(0);
    default:
      usage(2);
    }

  restore.reset();

  std::vector<char *> cmd(argv + optind, argv + argc);
  if (opt_u) {
    if (opt_D || !opt_d.empty() || !cmd.empty())
      usage(2);
    conf.unmount();
    return;
  }
  if (!opt_D && !std::ranges::contains(opt_d, cwd)) {
    if (!cmd.empty() && cwd == canonical(conf.homepath_)) {
      std::string name = prog.filename().string();
      std::string cmdstr;
      for (const auto &arg : cmd) {
        if (!cmdstr.empty())
          cmdstr += ' ';
        cmdstr += arg;
      }
      std::println(
          R"({0}: Refusing to expose your entire home directory to sandbox.  Did
{1:>{2}}  you forget to specify the -D option?  If you really want to grant
{1:>{2}}  permissions on your entire home directory, run
{1:>{2}}    jai -Dd {3} {4})",
          name, "", name.size(), conf.homepath_.string(), cmdstr);
      exit(1);
    }
    opt_d.emplace_back(cwd);
  }

  auto fd = conf.make_ns(opt_d);
  if (!cmd.empty()) {
    cmd.push_back(nullptr);
    conf.run(*fd, cwd, cmd.data());
  }
}

int
main(int argc, char **argv)
{
  umask(022);
  if (argc > 0)
    prog = argv[0];
  else
    prog = "jai";

  try {
    do_main(argc, argv);
  } catch (const std::exception &e) {
    std::println(stderr, "{}: {}", prog.string(), e.what());
    return 1;
  }
  return 0;
}
