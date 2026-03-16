#include "jai.h"
#include "config.h"
#include "cred.h"
#include "fs.h"
#include "options.h"

#include <cassert>
#include <cstring>
#include <filesystem>
#include <print>

#include <acl/libacl.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

path prog;

constexpr const char *kUnstrustedUser = UNTRUSTED_USER;
constexpr const char *kRunRoot = "/run/jai";

struct Config {
  enum Mode { kInvalidMode, kCasual, kStrict };

  Mode mode_{kInvalidMode};
  PathSet grant_directories_;
  bool grant_cwd_{true};
  std::set<std::string> env_filter_;
  path cwd_;
  std::string shellcmd_;
  PathSet mask_files_;
  bool mask_warn_{false};

  std::string user_;
  path homepath_;
  path sandbox_name_;
  Credentials user_cred_;
  Credentials untrusted_cred_;
  mode_t old_umask_ = 0755;

  Fd home_fd_;
  Fd home_jai_fd_;
  Fd run_jai_fd_;
  Fd run_jai_user_fd_;

  PathSet config_loop_detect_;

  void init_credentials();
  Fd make_idmap_ns();
  Fd make_mnt_ns();
  void exec(int nsfd, char **argv);
  void unmount();
  void unmountall();
  std::unique_ptr<Options> opt_parser();
  void make_default_conf();

  bool parse_config_file(path file, Options *opts = nullptr);
  void sanitize_env();

  [[nodiscard]] static Defer asuser(const Credentials *crp);
  [[nodiscard]] Defer asuser() { return asuser(&user_cred_); }
  void check_user(int fd, std::string path_for_error = {},
                  bool untrusted_ok = false);
  Fd ensure_udir(int dfd, const path &p, mode_t perm = 0700,
                 FollowLinks follow = kFollow)
  {
    auto _restore = asuser();
    Fd fd = ensure_dir(dfd, p, perm, follow);
    check_user(*fd);
    return fd;
  }

  int home();
  int home_jai();
  int run_jai();
  int run_jai_user();
  const path &cwd()
  {
    if (cwd_.empty()) {
      auto restore = asuser();
      cwd_ = canonical(std::filesystem::current_path());
    }
    return cwd_;
  }

  Fd make_blacklist(int dfd, path name);
  Fd make_home_overlay();
  Fd make_private_tmp();

  static bool name_ok(path p)
  {
    return p.is_relative() && std::ranges::distance(p.begin(), p.end()) == 1 &&
           *p.c_str() != '.';
  }
  void mask_warn()
  {
    if (mask_warn_) {
      warn("--mask did nothing because ~/.jai/{}.changes already existed",
           sandbox_name_.string());
      mask_warn_ = false;
    }
  }
};

bool
Config::parse_config_file(path file, Options *opts)
{
  auto ld = homepath_ / file;
  if (auto [_it, ok] = config_loop_detect_.insert(ld); !ok) {
    warn("{}: configuration loop", file.string());
    return false;
  }
  Defer _clear{[this, ld = std::move(ld)] { config_loop_detect_.erase(ld); }};

  auto r = try_read_file(home_jai(), file);
  if (!r) {
    if (r.error().code() == std::errc::no_such_file_or_directory)
      return false;
    throw r.error();
  }
  if (opts)
    opts->parse_file(*r, fdpath(home_jai(), file));
  else
    opt_parser()->parse_file(*r, fdpath(home_jai(), file));
  return true;
}

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
Config::init_credentials()
{
  auto realuid = getuid();

  const char *envuser{};
  if (!user_.empty())
    envuser = user_.c_str();
  else if (const char *u = getenv("SUDO_USER"))
    envuser = u;
  else if (const char *u = getenv("USER"))
    envuser = u;

  PwEnt pw;
  if (realuid == 0 && envuser) {
    if (!(pw = PwEnt::get_nam(envuser)))
      err("cannot find password entry for user {}", envuser);
  }
  else if (!(pw = PwEnt::get_id(realuid)))
    err("cannot find password entry for uid {}", realuid);

  user_ = pw->pw_name;
  homepath_ = pw->pw_dir;
  untrusted_cred_ = user_cred_ = Credentials::get_user(pw);

  if (PwEnt u = PwEnt::get_nam(kUnstrustedUser)) {
    if (u->pw_uid && !strcmp(u->pw_gecos, "JAI sandbox untrusted user") &&
        !strcmp(u->pw_dir, "/"))
      untrusted_cred_ = Credentials::get_user(u);
    else
      warn(R"(Ignoring user {} because uid is 0, home dir is not "/" or
GECOS field is not "JAI sandbox untrusted user")",
           kUnstrustedUser);
  }
  else
    warn(R"(Could not find credentials for untrusted {} user.
Try running "sudo systemd-sysusers".)",
         kUnstrustedUser);

  // Paranoia about ptrace, because we will drop privileges to access
  // the file system as the user.
  prctl(PR_SET_DUMPABLE, 0);

  old_umask_ = umask(0);
}

Defer
Config::asuser(const Credentials *crp)
{
  if (!crp->uid_) // target is root, nothing to do
    return {};
  auto old = Credentials::get_effective();
  if (old.uid_) {
    if (old.uid_ == crp->uid_) // we are already the target user
      return {};
    err("Config::asuser: want uid {} but already uid {}", crp->uid_, old.uid_);
  }
  crp->make_effective();
  return Defer{[old = std::move(old)] { old.make_effective(); }};
}

void
Config::check_user(int fd, std::string p, bool untrusted_ok)
{
  if (auto sb = xfstat(fd); sb.st_uid != user_cred_.uid_) {
    if (!untrusted_ok)
      err("{}: owned by {} should be owned by {}", p.empty() ? fdpath(fd) : p,
          sb.st_uid, user_cred_.uid_);
    else if (sb.st_uid != untrusted_cred_.uid_)
      err("{}: owned by {} should be owned by {} or {}",
          p.empty() ? fdpath(fd) : p, sb.st_uid, user_cred_.uid_,
          untrusted_cred_.uid_);
  }
}

int
Config::home_jai()
{
  if (!home_jai_fd_)
    home_jai_fd_ = ensure_udir(home(), ".jai");
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
    auto text =
        std::format("u::rwx,g::---,o::---,u:{}:r-x,m::r-x", user_cred_.uid_);
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

Fd
Config::make_blacklist(int dfd, path name)
{
  Fd blacklistfd = ensure_dir(dfd, name.c_str(), 0700, kFollow);
  check_user(*blacklistfd);
  if (!is_dir_empty(*blacklistfd)) {
    mask_warn();
    return blacklistfd;
  }

  for (path p : mask_files_) {
    try {
      make_whiteout(*blacklistfd, p);
    } catch (const std::exception &e) {
      warn("{}", e.what());
    }
  }

  return blacklistfd;
}

Fd
Config::make_home_overlay()
{
  path sb = cat(sandbox_name_, ".home");
  auto r = lock_or_validate_file(
      run_jai_user(), sb, O_RDONLY | O_DIRECTORY,
      [](int fd) { return is_mountpoint(fd); }, ".lock");
  if (r) {
    mask_warn();
    return std::move(*r);
  }

  Fd sandboxed_home = ensure_dir(run_jai_user(), sb, 0755, kFollow, true);
  if (is_mountpoint(*sandboxed_home))
    return sandboxed_home;

  auto restore = asuser();
  Fd changes = make_blacklist(home_jai(), cat(sandbox_name_, ".changes"));
  Fd work = ensure_udir(home_jai(), cat(sandbox_name_, ".work"));
  restore.reset();

  Fd fsfd = xfsopen("overlay", cat("jai-", sb).c_str());
  if (fsconfig(*fsfd, FSCONFIG_SET_FD, "lowerdir+", nullptr, home()) ||
      fsconfig(*fsfd, FSCONFIG_SET_FD, "upperdir", nullptr, *changes) ||
      fsconfig(*fsfd, FSCONFIG_SET_FD, "workdir", nullptr, *work))
    syserr("fsconfig(FSCONFIG_SET_FD)");
  Fd mnt = make_mount(*fsfd);

  xmnt_move(*mnt, *sandboxed_home);
  restore = asuser();
  return xopenat(run_jai_user(), sb, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
}

Fd
Config::make_private_tmp()
{
  auto r = lock_or_validate_file(
      run_jai_user(), "tmp", O_RDONLY | O_DIRECTORY,
      [](int fd) { return is_mountpoint(fd); }, ".lock");
  if (r)
    return ensure_dir(**r, sandbox_name_, 01777, kNoFollow);

  Fd tmp = ensure_dir(run_jai_user(), "tmp", 0755, kFollow);
  if (!is_mountpoint(*tmp)) {
    xmnt_move(*make_tmpfs("jai-tmp", "gid", "0", "mode", "0755", "size", "40%"),
              *tmp);
  }
  return ensure_dir(run_jai_user(), "tmp" / sandbox_name_, 01777, kNoFollow);
}

Fd
Config::make_idmap_ns()
{
  pid_t pid{-1};
  Defer _reap([pid] {
    if (pid > 0) {
      while (waitpid(pid, nullptr, 0) == -1 && errno == EINTR)
        ;
    }
  });
  auto pfds = xpipe();
  if (!(pid = xfork(CLONE_NEWUSER))) {
    pfds[1].reset();
    char c;
    read(*pfds[0], &c, 1);
    _exit(0);
  }
  pfds[0].reset();

  path child = std::format("/proc/{}", pid);

  Fd newns = xopenat(-1, child / "ns/user", O_RDONLY);

  Fd mapctl = xopenat(-1, child / "gid_map", O_WRONLY);
  auto map = make_id_map(user_cred_.gid_, untrusted_cred_.gid_);
  if (write(*mapctl, map.data(), map.size()) == -1)
    syserr("write(gid_map)");

  mapctl = xopenat(-1, child / "uid_map", O_WRONLY);
  map = make_id_map(user_cred_.uid_, untrusted_cred_.uid_);
  if (write(*mapctl, map.data(), map.size()) == -1)
    syserr("write(uid_map)");
  mapctl.reset();

  return newns;
}

Fd
Config::make_mnt_ns()
{
  Fd oldns = xopenat(-1, "/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  Defer _restore_ns{[fd = *oldns] { xsetns(fd, CLONE_NEWNS); }};

  if (mode_ == kInvalidMode)
    mode_ = sandbox_name_.empty() ? kCasual : kStrict;
  if (sandbox_name_.empty())
    sandbox_name_ = "default";

  mount_attr attr{
      .attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
      .propagation = MS_PRIVATE,
  };
  Fd tmp = clone_tree(*make_private_tmp());

  Fd home;
  Fd mapns;
  Credentials *sbcred = &user_cred_;
  if (mode_ == kCasual)
    home = clone_tree(*make_home_overlay());
  else {
    sbcred = &untrusted_cred_;
    mapns = make_idmap_ns();
    attr.attr_set |= MOUNT_ATTR_IDMAP;
    attr.userns_fd = *mapns;
    home = clone_tree(*ensure_udir(home_jai(), cat(sandbox_name_, ".home")));
  }
  xmnt_setattr(*tmp, attr);
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

  if (grant_cwd_) {
    if (!grant_directories_.contains(cwd())) {
      if (cwd() == homepath_) {
        std::string name = prog.filename().string();
        std::println(
            R"({0}: Refusing to expose your entire home directory to sandbox.  Did
{1:>{2}}  you forget to specify the -D option?  If you really want to grant
{1:>{2}}  permissions on your entire home directory, use both -D and -d, as in
{1:>{2}}    {0} -Dd {3} ...)",
            name, "", name.size(), homepath_.string());
        exit(1);
      }
      grant_directories_.emplace(cwd());
    }
  }

  for (auto d : grant_directories_) {
    if (d.is_relative())
      d = "/" / d;
    xsetns(*oldns, CLONE_NEWNS);
    auto restore_root = asuser();
    Fd src = xopenat(-1, d, O_DIRECTORY | O_PATH | O_CLOEXEC);
    restore_root.reset();
    src = clone_tree(*src); // Should it be recursive?
    xmnt_setattr(*src, attr);

    xsetns(*newns, CLONE_NEWNS);
    restore_root = asuser();
    Fd dst = openat(-1, d.c_str(), O_DIRECTORY | O_PATH | O_CLOEXEC);
    if (!dst) {
      if (mode_ == kCasual || (errno != EACCES && errno != ENOENT))
        syserr("{}", d.string());
      restore_root.reset();
      restore_root = asuser(sbcred);
      dst = ensure_dir(-1, d, 0755, kNoFollow, true);
    }
    check_user(*dst, d, true);
    restore_root.reset();
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

  auto runuser = path(kRunRoot) / user_;
  for (const char *ext : {".home", ".tmp"}) {
    auto mp = runuser / cat(sandbox_name_, ext);
    umount2(mp.c_str(), UMOUNT_NOFOLLOW);
    unlinkat(run_jai_user(), mp.filename().c_str(), AT_REMOVEDIR);
  }

  unlinkat(run_jai_user(), ".lock", 0);
  lock.reset();
  unlinkat(run_jai(), user_.c_str(), AT_REMOVEDIR);
}

static void
clean_root_owned_dir(int dfd, path file)
{
  Fd target = openat(dfd, file.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (!target) {
    warn("{}: {}", fdpath(dfd, file), strerror(errno));
    return;
  }
  if (!is_fd_at_path(dfd, *target, "..", kNoFollow)) {
    warn("{}: ignored (possible TOCTTOU problem)", fdpath(dfd, file));
    return;
  }
  auto d = xopendir(*target);
  while (auto de = readdir(d)) {
    struct stat sb;
    if (fstatat(*target, d_name(de), &sb, AT_SYMLINK_NOFOLLOW)) {
      warn("fstatat {}: {}", fdpath(*target, d_name(de)), strerror(errno));
      continue;
    }
    else if (!S_ISDIR(sb.st_mode) &&
             (sb.st_size == 0 || !S_ISREG(sb.st_mode))) {
      if (unlinkat(*target, d_name(de), 0))
        warn("unlinkat {}: {}", fdpath(*target, d_name(de)), strerror(errno));
      else
        warn("deleted {}", fdpath(*target, d_name(de)));
    }
  }
}

void
Config::unmountall()
{
  Fd lock;
  while (!(lock = open_lockfile(run_jai_user(), ".lock")))
    ;
  recursive_umount(path(kRunRoot) / user_, false);

  auto dir = xopendir(run_jai_user());
  while (auto de = readdir(dir))
    unlinkat(run_jai_user(), de->d_name, AT_REMOVEDIR);

  // Get rid of any stale files the user can't delete
  try {
    auto restore = asuser();
    auto jd = xopendir(home_jai());
    while (auto de = readdir(jd)) {
      path name = d_name(de);
      if (name.extension() == ".work")
        try {
          Fd work = xopenat(home_jai(), name.c_str(), O_RDONLY | O_DIRECTORY);
          check_user(*work);
          restore.reset();
          Defer _unrestore([&restore, this] { restore = asuser(); });
          clean_root_owned_dir(*work, "work");
          clean_root_owned_dir(*work, "index");
        } catch (const std::exception &e) {
          warn("{}", e.what());
        }
    }
  } catch (const std::exception &e) {
    warn("{}", e.what());
  }

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
    // Suffixes
    "*_ACCESS_KEY",
    "*_API_KEY",
    "*_APIKEY",
    "*_AUTH",
    "*_AUTH_TOKEN",
    "*_CONNECTION_STRING",
    "*_CREDENTIAL",
    "*_CREDENTIALS",
    "*_PASSWD",
    "*_PASSWORD",
    "*_PID",
    "*_PRIVATE_KEY",
    "*_PWD",
    "*_SECRET",
    "*_SECRET_KEY",
    "*_SOCK",
    "*_SOCKET",
    "*_SOCKET_PATH",
    "*_TOKEN",
});

const auto default_masklist = std::to_array<const char *>({
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

void
Config::make_default_conf()
{
  auto fd = xopenat(home_jai(), ".", O_RDWR | O_TMPFILE | O_CLOEXEC, 0600);
  std::string text =
      R"(# The executed process will have PID 1, which can confuse some
# programs.  Adding "; exit $?" after the command and arguments will
# cause bash to fork and stay around, so command "$0" has PID 2.

command "$0" "$@"; exit $?

# Masked file wills be deleted when a new overlayfs is first created,
# but have no effect on existing overlays.  To delete files from an
# existing overlay, delete them under /run/jai/$USER/default.home.  If
# you want to start over with a fresh overlay, you can run "jai -u" to
# unmount any existing overlays, then remove the directory
# $HOME/.jai/$USER/default.changes.  The next time you run jai, it
# will create a new overlay masking all of the files below.

)";
  for (auto p : default_masklist)
    text += std::format("mask {}\n", p);

  text += R"(
# The following environment variables will be removed from sandboxed
# environments.  You can use * as a wildcard to match any variables
# matching the pattern.

)";
  for (auto e : env_blacklist)
    text += std::format("unsetenv {}\n", e);

  errno = EAGAIN;
  if (write(*fd, text.data(), text.size()) != text.size())
    syserr("write(O_TMPFILE for default.conf)");
  if (linkat(*fd, "", home_jai(), "default.conf", AT_EMPTY_PATH) &&
      errno != EEXIST)
    syserr("linkat({})", fdpath(home_jai(), "default.conf"));
}

extern "C" char **environ;

void
Config::sanitize_env()
{
  std::vector<std::string_view> patterns;

  for (const auto &v : env_filter_) {
    if (v.find('*') == v.npos)
      unsetenv(v.c_str());
    else if (std::ranges::count(v, '*') <= 4)
      patterns.push_back(v);
    else
      // Too many *s could cause a lot of backtracking
      warn(R"(ignoring env pattern "{}" with too many '*'s)", v);
  }

  std::vector<std::string> to_remove;
  for (char **v = environ; *v; ++v) {
    std::string_view sv(*v);
    if (auto eq = sv.find('='); eq != sv.npos)
      sv = sv.substr(0, eq);
    for (auto pat : patterns)
      if (glob(pat, sv)) {
        to_remove.push_back(std::string{sv});
        break;
      }
  }
  for (const auto &v : to_remove)
    unsetenv(v.c_str());
}

void
Config::exec(int nsfd, char **argv)
{
  if (unshare(CLONE_NEWPID | CLONE_NEWIPC))
    syserr("unshare(CLONE_NEWPID)");

  if (auto pid = xfork()) {
    close(nsfd);
    int status;
    while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
      ;
    // unmount();
    if (WIFEXITED(status))
      exit(WEXITSTATUS(status));
    if (WIFSIGNALED(status)) {
      signal(WTERMSIG(status), SIG_DFL);
      raise(WTERMSIG(status));
    }
    _exit(1);
  }

  try {
    xsetns(nsfd, CLONE_NEWNS);
    recursive_umount("/proc");
    xmnt_move(*make_mount(*xfsopen("proc", "proc"), MOUNT_ATTR_NOSUID |
                                                        MOUNT_ATTR_NODEV |
                                                        MOUNT_ATTR_NOEXEC),
              -1, "/proc");
  } catch (const std::exception &e) {
    warn("{}", e.what());
    _exit(1);
  }

  if (mode_ == kCasual)
    user_cred_.make_real();
  else
    untrusted_cred_.make_real();
  if (chdir(cwd().c_str()))
    syserr("chdir({})", cwd().string());
  sanitize_env();
  umask(old_umask_);
  const char *argv0 = argv[0];
  std::vector<const char *> bashcmd;
  if (!shellcmd_.empty()) {
    argv0 = PATH_BASH;
    bashcmd.push_back("init");
    bashcmd.push_back("-c");
    bashcmd.push_back(shellcmd_.c_str());
    while (*argv)
      bashcmd.push_back(*(argv++));
    bashcmd.push_back(nullptr);
    argv = const_cast<char **>(bashcmd.data());
  }
  execvp(argv0, argv);
  perror(argv0);
  _exit(1);
}

std::unique_ptr<Options>
Config::opt_parser()
{
  auto ret = std::make_unique<Options>();
  Options &opts = *ret;
  opts(
      "-d", "--dir",
      [this](path d) { grant_directories_.emplace(canonical(d)); },
      "Grant full access to DIR", "DIR");
  opts(
      "-D", "--nocwd", [this] { grant_cwd_ = false; },
      "Do not grant access to current working directory");
  opts(
      "-n", "--name",
      [this](path sb) {
        if (!name_ok(sb))
          err<Options::Error>("{}: invalid sandbox name", sb.string());
        sandbox_name_ = sb;
      },
      "Use private or overlay home directory NAME", "NAME");
  opts(
      "--mask",
      [this](path p) {
        if (p.is_absolute())
          err<Options::Error>("{}: cannot mask an absolute path", p.string());
        mask_files_.emplace(std::move(p));
      },
      "Erase $HOME/FILE when first creating overlay home", "FILE");
  opts("--conf", [this, opts = ret.get()](path file) {
    if (!parse_config_file(file, opts))
      err<Options::Error>("{}: configuration file not found", file.string());
  });
  opts(
      "--strict", [this] { mode_ = kStrict; },
      std::format("Enable strict mode (run with uid {} and empty home)",
                  kUnstrustedUser));
  opts(
      "--casual", [this] { mode_ = kCasual; },
      "Enable casual mode (copy-on-write overlay home directory)");
  opts(
      "--unsetenv",
      [this](std::string var) { env_filter_.emplace(std::move(var)); },
      "Remove VAR from environment (VAR can contain wildcard '*')", "VAR");
  opts(
      "--command", [this](std::string cmd) { shellcmd_ = std::move(cmd); },
      R"(Bash command line to execute program (default: "$0" "$@"))", "CMD");
  return ret;
}

std::string option_help;

[[noreturn]] static void
usage(int status)
{
  std::print(status ? stderr : stdout,
             "usage: {0} [OPTIONS] [CMD [ARG...]]\n{1}",
             prog.filename().string(), option_help);
  exit(status);
}

[[noreturn]] static void
version()
{
  std::println(R"({}
Copyright (C) 2026 David Mazieres
This program comes with NO WARRANTY, to the extent permitted by law.
You may redistribute it under the terms of the GNU General Public License
version 3 or later; see the file named COPYING for details.)",
               PACKAGE_STRING);
  exit(0);
}

void
do_main(int argc, char **argv)
{
  Config conf;
  conf.init_credentials();
  auto restore = conf.asuser();
  conf.cwd(); // compute and cache while privileges lowered

  bool opt_u{};
  std::vector<path> opt_d;
  path opt_C = "";

  auto opts = conf.opt_parser();
  // A few options not available in config files
  (*opts)("-u", [&] { opt_u = true; }, "Unmount sandboxed file systems");
  // Override inline conf to make CLI idempotent
  (*opts)(
      "-C", "--conf", [&](path p) { opt_C = p; },
      R"(Use FILE as configuration file (relative to ~/.jai)
default: CMD.conf or default.conf if CMD.conf does not exist)",
      "FILE");
  (*opts)("--help", [] { usage(1); });
  (*opts)("--version", version, "Print copyright and version then exit");
  option_help = opts->help();

  std::vector<char *> cmd;
  try {
    cmd.assign_range(opts->parse_argv(argc, argv));
  } catch (Options::Error &e) {
    std::println("{}", e.what());
    usage(2);
  }
  if (!conf.mask_files_.empty())
    conf.mask_warn_ = true;

  if (opt_u) {
    if (!conf.grant_cwd_ || !conf.grant_directories_.empty() || !cmd.empty()) {
      std::println("-u is not compatible with -d, -D, or a command");
      usage(2);
    }
    restore.reset();
    conf.unmountall();
    return;
  }

  if (opt_C.empty() && !cmd.empty() && conf.name_ok(cmd[0]))
    opt_C = std::format("{}.conf", cmd[0]);
  if ((opt_C.empty() || !conf.parse_config_file(opt_C)) &&
      !conf.parse_config_file("default.conf")) {
    conf.make_default_conf();
    conf.parse_config_file("default.conf");
  }

  restore.reset();

  auto fd = conf.make_mnt_ns();
  if (!cmd.empty()) {
    cmd.push_back(nullptr);
    conf.exec(*fd, cmd.data());
  }
}

int
main(int argc, char **argv)
{
  if (argc > 0)
    prog = argv[0];
  else
    prog = PACKAGE_TARNAME;

  try {
    do_main(argc, argv);
  } catch (const std::exception &e) {
    warn("{}", e.what());
    return 1;
  }
  return 0;
}
