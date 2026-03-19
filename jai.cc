#include "jai.h"
#include "config.h"
#include "cred.h"
#include "fs.h"
#include "options.h"

#include <cassert>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <linux/prctl.h>
#include <print>

#include <acl/libacl.h>
#include <pwd.h>
#include <ranges>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

path prog;

constexpr const char *kUntrustedUser = UNTRUSTED_USER;
constexpr const char *kUntrustedGecos = "JAI sandbox untrusted user";
constexpr const char *kRunRoot = "/run/jai";

struct Config {
  enum Mode { kInvalidMode, kCasual, kBare, kStrict };

  Mode mode_{kInvalidMode};
  PathSet grant_directories_;
  bool grant_cwd_{true};
  std::set<std::string, std::less<>> env_filter_;
  std::map<std::string, std::string, std::less<>> setenv_;
  path cwd_;
  std::string shellcmd_;
  PathSet mask_files_;
  bool mask_warn_{};
  bool dir_relative_to_home_{};

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
  void unmountall();
  std::unique_ptr<Options> opt_parser();

  bool parse_config_file(path file, Options *opts = nullptr);
  std::vector<const char *> make_env();

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
  int storage();
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
  Fd make_private_passwd();

  static bool name_ok(path p)
  {
    return p.is_relative() && std::ranges::distance(p.begin(), p.end()) == 1 &&
           *p.c_str() != '.';
  }
  void mask_warn()
  {
    if (mask_warn_) {
      warn(R"(--mask ignored because {5}/{0}/{1}.home already mounted.
{2:>{3}}  Run "{4} -u" to unmount overlays.)",
           user_, sandbox_name_.string(), "", prog.filename().string().size(),
           prog.filename().string(), kRunRoot);
      mask_warn_ = false;
    }
  }
};

bool
Config::parse_config_file(path file, Options *opts)
{
  bool slash = std::ranges::distance(file.begin(), file.end()) > 1;
  auto ld = (slash ? cwd() : homejaipath_) / file;
  if (auto [_it, ok] = config_loop_detect_.insert(ld); !ok)
    err<Options::Error>("configuration loop");
  Defer _clear{[this, ld = std::move(ld), drh = dir_relative_to_home_] {
    config_loop_detect_.erase(ld);
    if (!drh)
      dir_relative_to_home_ = false;
  }};
  dir_relative_to_home_ = true;

  auto r = try_read_file(slash ? AT_FDCWD : home_jai(), file);
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
  shell_ = pw->pw_shell;
  untrusted_cred_ = user_cred_ = Credentials::get_user(pw);

  if (PwEnt u = PwEnt::get_nam(kUntrustedUser)) {
    if (u->pw_uid && !strcmp(u->pw_gecos, kUntrustedGecos) &&
        !strcmp(u->pw_dir, "/"))
      untrusted_cred_ = Credentials::get_user(u);
    else
      warn(R"(Ignoring user {} because uid is 0, home dir is not "/", or
GECOS field is not "{}")",
           kUntrustedUser, kUntrustedGecos);
  }

  const char *jcd = getenv("JAI_CONFIG_DIR");
  homejaipath_ = homejaipath_ / (jcd ? jcd : ".jai");

  // Paranoia about ptrace, because we will drop privileges to access
  // the file system as the user.
  if (prctl(PR_SET_DUMPABLE, 0) == -1)
    syserr("prctl(PR_SET_DUMPABLE, 0)");

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
    home_jai_fd_ = ensure_udir(home(), homejaipath_);
  return *home_jai_fd_;
}

int
Config::storage()
{
  if (storagedir_.empty())
    return home_jai();
  if (!storage_fd_)
    storage_fd_ = ensure_udir(AT_FDCWD, storagedir_);
  return *storage_fd_;
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
  if (is_mountpoint(*blacklistfd))
    err("{}: directory must not be a mountpoint", fdpath(*blacklistfd));

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
  auto chgpath = cat(sandbox_name_, ".changes");
  Fd changes = make_blacklist(storage(), chgpath);
  Fd work = ensure_udir(*changes, ".." / cat(sandbox_name_, ".work"));
  restore.reset();

  Fd fsfd = xfsopen("overlay", cat("jai-", sb).c_str());
  auto xsetfd = [&](const char *param, int fd) {
    if (fsconfig(*fsfd, FSCONFIG_SET_FD, param, nullptr, fd))
      syserr("fsconfig(FSCONFIG_SET_FD, \"{}\")", param);
  };
  xsetfd("lowerdir+", home());
  xsetfd("upperdir", *changes);
  xsetfd("workdir", *work);
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
Config::make_private_passwd()
{
  if (Fd fd = openat(run_jai_user(), "passwd", O_RDONLY | O_CLOEXEC))
    return fd;
  if (errno != ENOENT)
    syserr("{}", fdpath(run_jai_user(), "passwd"));

  RaiiHelper<fclose> r, w;

  Fd wfd = xopenat(run_jai_user(), ".", O_RDWR | O_TMPFILE | O_CLOEXEC, 0444);
  if (!(w = fdopen(*wfd, "w")))
    syserr("fdopen({})", fdpath(*wfd));
  wfd.release();

  auto restore = asuser();
  r = fopen("/etc/passwd", "r");
  if (!r)
    syserr("/etc/passwd");
  fcntl(fileno(r), F_SETFD, 1);
  restore.reset();

  while (auto pw = PwEnt::find(fgetpwent_r, *r)) {
    if (!strcmp(pw->pw_name, kUntrustedUser)) {
      pw.get()->pw_dir = const_cast<char *>(homepath_.c_str());
      pw.get()->pw_shell = const_cast<char *>(shell_.c_str());
    }
    if (putpwent(pw.get(), *w))
      syserr("putpwent");
  }
  if (fflush(*w))
    syserr("fflush");
  if (linkat(fileno(*w), "", run_jai_user(), "passwd", AT_EMPTY_PATH) &&
      errno != EEXIST)
    syserr("linkat({})", fdpath(run_jai_user(), "passwd"));
  r.reset();
  w.reset();

  return xopenat(run_jai_user(), "passwd", O_RDONLY);
}

Fd
Config::make_idmap_ns()
{
  pid_t pid{-1};
  Defer _reap([&pid] {
    if (pid > 0) {
      kill(pid, SIGKILL);
      while (waitpid(pid, nullptr, 0) == -1 && errno == EINTR)
        ;
    }
  });
  if (!(pid = xfork(CLONE_NEWUSER))) {
    pause();
    _exit(0);
  }

  path child = std::format("/proc/{}", pid);
  Fd newns = xopenat(-1, child / "ns/user", O_RDONLY | O_CLOEXEC);

  Fd mapctl = xopenat(-1, child / "gid_map", O_WRONLY | O_CLOEXEC);
  auto map = make_id_map(user_cred_.gid_, untrusted_cred_.gid_);
  if (write(*mapctl, map.data(), map.size()) == -1)
    syserr("write(gid_map)");

  mapctl = xopenat(-1, child / "uid_map", O_WRONLY | O_CLOEXEC);
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

  bool strict_ok = untrusted_cred_ != user_cred_;
  if (mode_ == kStrict && !strict_ok)
    err("Cannot use strict mode: invalid user {}", kUntrustedUser);

  if (mode_ == kInvalidMode)
    mode_ = sandbox_name_.empty() ? kCasual : strict_ok ? kStrict : kBare;
  if (sandbox_name_.empty())
    sandbox_name_ = "default";

  mount_attr attr{
      .attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
      .propagation = MS_PRIVATE,
  };
  Fd tmp = clone_tree(*mp_holder_.emplace_back(make_private_tmp()));

  Fd passwd;
  if (mode_ == kStrict)
    passwd = clone_tree(*make_private_passwd());

  Fd home;
  Fd mapns;
  Credentials *sbcred = &user_cred_;
  if (mode_ == kCasual)
    home = clone_tree(*mp_holder_.emplace_back(make_home_overlay()));
  else {
    if (mode_ == kStrict) {
      sbcred = &untrusted_cred_;
      mapns = make_idmap_ns();
      attr.attr_set |= MOUNT_ATTR_IDMAP;
      attr.userns_fd = *mapns;
    }
    home = clone_tree(*ensure_udir(storage(), cat(sandbox_name_, ".home")));
  }
  xmnt_setattr(*tmp, attr);
  xmnt_setattr(*home, attr);
  if (passwd)
    xmnt_setattr(*passwd, attr);

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
  if (passwd)
    xmnt_move(*passwd, -1, "/etc/passwd");

  if (grant_cwd_) {
    if (!grant_directories_.contains(cwd())) {
      if (cwd() == homepath_) {
        std::string name = prog.filename().string();
        warn(
            R"(Refusing to expose your entire home directory to sandbox.  Did
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
    check_user(*src, d);
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
  auto mp = runuser / cat(sandbox_name_, ".home");
  umount2(mp.c_str(), UMOUNT_NOFOLLOW);
  unlinkat(run_jai_user(), mp.filename().c_str(), AT_REMOVEDIR);

  unlinkat(run_jai_user(), ".lock", 0);
  lock.reset();
  unlinkat(run_jai(), user_.c_str(), AT_REMOVEDIR);
}

static void
clean_root_owned_dir(int dfd, path file)
{
  Fd target = openat(dfd, file.c_str(),
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (!target) {
    if (errno != ENOENT)
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
  bool unmount_ok = recursive_umount(path(kRunRoot) / user_, false);

  auto dir = xopendir(run_jai_user());
  while (auto de = readdir(dir))
    if (unlinkat(run_jai_user(), de->d_name, AT_REMOVEDIR) && errno == ENOTDIR)
      unlinkat(run_jai_user(), de->d_name, 0);

  // Get rid of any stale files the user can't delete
  if (unmount_ok)
    try {
      auto restore = asuser();
      auto jd = xopendir(storage());
      while (auto de = readdir(jd)) {
        path name = d_name(de);
        if (name.extension() == ".changes")
          try {
            path workpath = name / ".." / cat(name.stem(), ".work");
            Fd work = xopenat(home_jai(), workpath.c_str(),
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
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

extern "C" char **environ;

std::vector<const char *>
Config::make_env()
{
  std::vector<std::string_view> filter_patterns;
  std::set<std::string_view, std::less<>> filter_vars;
  for (const auto &v : env_filter_)
    if (v.find('*') == v.npos)
      filter_vars.insert(v);
    else
      filter_patterns.push_back(v);

  for (char **e = environ; *e; ++e) {
    std::string_view sv(*e);
    if (auto eq = sv.find('='); eq != sv.npos)
      sv = sv.substr(0, eq);
    else
      continue;
    if (filter_vars.contains(sv) ||
        std::ranges::any_of(filter_patterns,
                            [sv](auto pat) { return glob(pat, sv); }))
      continue;
    setenv_.try_emplace(std::string(sv), *e);
  }

  std::vector<const char *> ret(std::from_range,
                                setenv_ | std::views::transform([](auto &kv) {
                                  return kv.second.c_str();
                                }));
  ret.push_back(nullptr);
  return ret;
}

// Exits if child pid exited, returns stop signal if pid stopped
static int
propagate_exit(int pid, bool immediate)
try {
  assert(pid > 0);
  int status;
again:
  if (auto r = waitpid(-1, &status, WUNTRACED); r == -1) {
    if (errno == EINTR)
      goto again;
    syserr("waitpid");
  }
  else if (r != pid)
    // PID 1 in the jail may need to reap reparented processes
    goto again;

  if (WIFSTOPPED(status)) {
    if (int sig = WSTOPSIG(status);
        sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU)
      return sig;
    // Unlikely to reach here, but maybe another process attached to
    // our child with the debugger and it got SIGTRAP or something?
    goto again;
  }

  // unmount();
  if (WIFEXITED(status))
    (immediate ? _exit : exit)(WEXITSTATUS(status));
  if (WIFSIGNALED(status)) {
    signal(WTERMSIG(status), SIG_DFL);
    raise(WTERMSIG(status));
    (immediate ? _exit : exit)(-1);
  }
  err("unknown child wait status 0x{:x}", status);
} catch (const std::exception &e) {
  warn("{}", e.what());
  immediate ? _exit(1) : exit(1);
}

void
Config::exec(int nsfd, char **argv)
{
  // This function is a bit annoying because the existing jai process
  // cannot move to a new PID namespace, so we have to fork once.  But
  // the forked process will have PID 1 and behave strangely (such as
  // not receiving signals), so needs to fork again to run the actual
  // jailed program with a normal PID.  Then PID 1 has to propagate
  // exit and stop events to the outer parent, which must propagate
  // them to the process than ran jai.
  //
  // Further complicating matters, PID 1 cannot stop itself (since it
  // cannot receive a SIGSTOP from within the PID namespace).  Hence,
  // if the jailed program stops, it uses a pipe to request that the
  // original jai process stop it (from outside the PID namespace).
  auto stop_me = xpipe();

  if (auto pid = xfork(CLONE_NEWPID | CLONE_NEWIPC)) {
    // This is the last process in the old PID namespace
    close(nsfd);
    stop_me[1].reset();
    char garbage[64];
    // discard first write, whose only purpose is to test the parent
    // didn't die before the child set PR_SET_PDEATSIG.
    read(*stop_me[0], garbage, 1);
    for (;;) {
      if (read(*stop_me[0], garbage, sizeof(garbage)) > 0)
        kill(pid, SIGSTOP);
      raise(propagate_exit(pid, false));
    }
  }
  stop_me[0].reset();

  if (auto pid = xfork()) {
    // This is the "init" process with PID 1 in the new namespace
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    // If the parent exited, users will be able to unmount overlay
    // file systems that still exist in other namespaces, which is
    // annoying and makes it hard to re-create them.  Write one byte
    // to the pipe to die of a SIGPIPE in case the parent died in the
    // brief moment before we set PR_SET_PDEATHSIG.  (getppid() won't
    // tell us if we got reparented to init since we are in a new PID
    // namespace.)
    if (write(*stop_me[1], "", 1) != 1) {
      warn("parent killed before PR_SET_PDEATHSIG");
      _exit(1);
    }
    prctl(PR_SET_NAME, "jai-init");

    static pid_t main_child_pid;
    main_child_pid = pid;
    signal(SIGCONT, +[](int sig) { kill(main_child_pid, sig); });

    for (;;) {
      propagate_exit(pid, true);
      write(*stop_me[1], "", 1);
    }
  }
  stop_me[1].reset();

  try {
    xsetns(nsfd, CLONE_NEWNS);
    recursive_umount("/proc");
    xmnt_move(*make_mount(*xfsopen("proc", "proc"), MOUNT_ATTR_NOSUID |
                                                        MOUNT_ATTR_NODEV |
                                                        MOUNT_ATTR_NOEXEC),
              -1, "/proc");

    if (mode_ == kCasual || mode_ == kBare)
      user_cred_.make_real();
    else
      untrusted_cred_.make_real();
    if (chdir(cwd().c_str()))
      syserr("chdir({})", cwd().string());
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

    setenv("JAI_NAME", sandbox_name_.c_str(), 1);
    setenv("JAI_MODE",
           mode_ == kStrict ? "strict"
           : mode_ == kBare ? "bare"
                            : "casual",
           1);
    auto env = make_env();

    execvpe(argv0, argv, const_cast<char **>(env.data()));
    perror(argv0);
    _exit(1);
  } catch (const std::exception &e) {
    warn("{}", e.what());
    _exit(1);
  }
}

std::unique_ptr<Options>
Config::opt_parser()
{
  auto ret = std::make_unique<Options>();
  Options &opts = *ret;
  opts(
      "-m", "--mode",
      [this](std::string_view m) {
        static const std::map<std::string, Mode, std::less<>> modemap{
            {"default", kInvalidMode},
            {"casual", kCasual},
            {"bare", kBare},
            {"strict", kStrict}};
        if (auto it = modemap.find(m); it != modemap.end())
          mode_ = it->second;
        else
          err<Options::Error>(R"(invalid mode {})", m);
      },
      std::format(R"(Set execution mode to one of the following:
    casual - run as invoking UID with overlay home directory
    bare - run as invoking UID with bare home directory
    strict - run as UID {} with bare home directory)",
                  kUntrustedUser),
      "casual|bare|strict");
  opts(
      "-d", "--dir",
      [this](path d) {
        grant_directories_.emplace(
            canonical(dir_relative_to_home_ ? homepath_ / d : d));
      },
      "Grant full access to DIR.", "DIR");
  opts(
      "-D", "--nocwd", [this] { grant_cwd_ = false; },
      "Do not grant access to the current working directory");
  opts(
      "-n", "--name",
      [this](path sb) {
        if (!name_ok(sb))
          err<Options::Error>("{}: invalid sandbox name", sb.string());
        sandbox_name_ = sb;
      },
      "Use private or overlay home directory named NAME", "NAME");
  opts("--conf", [this, opts = ret.get()](path file) {
    if (!parse_config_file(file, opts))
      err<Options::Error>("{}: configuration file not found", file.string());
  });
  opts(
      "--mask",
      [this](path p) {
        if (p.is_absolute())
          err<Options::Error>("{}: cannot mask an absolute path", p.string());
        mask_files_.emplace(std::move(p));
      },
      "Erase $HOME/FILE when first creating overlay home", "FILE");
  opts(
      "--unmask", [this](path p) { mask_files_.erase(p); },
      "Undo the effects of a previous --mask option", "FILE");
  opts(
      "--unsetenv",
      [this](std::string_view var) {
        erase_if(setenv_,
                 [var](const auto &it) { return glob(var, it.first); });
        env_filter_.emplace(var);
      },
      "Remove VAR (wich may contain wildcard '*') from the environment", "VAR");
  opts(
      "--setenv",
      [this](std::string var) {
        if (auto pos = var.find('='); pos != var.npos)
          setenv_.insert_or_assign(var.substr(0, pos), var);
        else if (auto it = env_filter_.find(var); it != env_filter_.end())
          env_filter_.erase(it);
        else if (var.contains(' '))
          // space almost certainly an error since it didn't match
          err<Options::Error>(
              R"(Environment variable "{}" contains space, did you mean '='?)",
              var);
        else if (const char *p = getenv(var.c_str());
                 p && std::ranges::any_of(env_filter_, [&var](const auto &pat) {
                   return glob(pat, var);
                 }))
          setenv_.insert_or_assign(var, std::format("{}={}", var, p));
      },
      "Undo the effects of --unsetenv=VAR, or set VAR=VALUE", "VAR[=VALUE]");
  opts(
      "--command", [this](std::string cmd) { shellcmd_ = std::move(cmd); },
      R"(Bash command line to execute program (default: "$0" "$@"))", "CMD");
  opts(
      "--storage",
      [this](std::string_view s) {
        if (dir_relative_to_home_)
          storagedir_ = homepath_ / s;
        else
          storagedir_ = s;
      },
      R"(Store overlay and private home directories in DIR
(default: $JAI_CONFIG_DIR or $HOME/.jai))",
      "DIR");
  return ret;
}

std::string option_help;

[[noreturn]] static void
usage(int status)
{
  if (status)
    std::println(stderr, "Try {} --help for more information.",
                 prog.filename().string());
  else
    std::print(stdout, "usage: {0} [OPTIONS] [CMD [ARG...]]\n{1}",
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
      R"(Use FILE as configuration file.  A file FILE with no '/'
is relative to $JAI_CONFIG_DIR if set, otherwise to ~/.jai.
The default is CMD.conf if it exists, otherwise default.conf)",
      "FILE");
  (*opts)("--help", [] { usage(0); });
  (*opts)("--version", version, "Print copyright and version then exit");
  (*opts)(
      "--print-defaults",
      [] {
        write(1, jai_defaults.data(), jai_defaults.size());
        exit(0);
      },
      "Show default contents of $JAI_CONFIG_DIR/.defaults");
  option_help = opts->help();

  std::vector<char *> cmd;
  try {
    cmd.assign_range(opts->parse_argv(argc, argv));
  } catch (Options::Error &e) {
    warn("{}", e.what());
    usage(2);
  }
  if (!conf.mask_files_.empty())
    conf.mask_warn_ = true;

  if (opt_u) {
    if (!conf.grant_cwd_ || !conf.grant_directories_.empty() || !cmd.empty()) {
      std::println(stderr, "-u is not compatible with -d, -D, or a command");
      usage(2);
    }
    restore.reset();
    conf.unmountall();
    return;
  }

  ensure_file(conf.home_jai(), ".defaults", jai_defaults, 0600);
  ensure_file(conf.home_jai(), "default.conf", jai_defaults, 0600);

  if (!opt_C.empty()) {
    if (!conf.parse_config_file(opt_C))
      err("{}: no such configuration file", opt_C.string());
  }
  else if ((cmd.empty() || !conf.name_ok(cmd[0]) ||
            !conf.parse_config_file(std::format("{}.conf", cmd[0]))) &&
           !conf.parse_config_file("default.conf"))
    conf.parse_config_file("default.conf");
  // Re-parse command line to override files
  opts->parse_argv(argc, argv);

  restore.reset();

  if (cmd.empty()) {
    const char *shell = conf.shell_.empty() ? "/bin/sh" : conf.shell_.c_str();
    cmd.push_back(const_cast<char *>(shell));
  }

  auto fd = conf.make_mnt_ns();
  cmd.push_back(nullptr);
  conf.exec(*fd, cmd.data());
}

int
main(int argc, char **argv)
{
  if (argc > 0)
    prog = argv[0];
  else
    prog = PACKAGE_TARNAME;

#if 1
  using ToCatch = std::exception;
#else
  struct ToCatch {
    auto what() const { return ""; }
  };
#endif

  try {
    do_main(argc, argv);
  } catch (const ToCatch &e) {
    warn("{}", e.what());
    return 1;
  }
  return 0;
}
