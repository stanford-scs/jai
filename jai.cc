#include "jai.h"
#include "fs.h"

#include <cassert>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <filesystem>
#include <linux/prctl.h>
#include <print>

#include <poll.h>
#include <pwd.h>
#include <ranges>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>

path prog;

void
Config::parse_config_fd(int fd, Options *opts)
{
  auto ld = fdpath(fd, true);
  if (auto [_it, ok] = config_loop_detect_.insert(ld); !ok)
    err<Options::Error>("configuration loop");
  Defer _clear([this, ld, pcf = parsing_config_file_] {
    config_loop_detect_.erase(ld);
    parsing_config_file_ = pcf;
  });
  parsing_config_file_ = true;
  auto go = [&](Options *o) { o->parse_file(read_file(fd), ld); };
  go(opts ? opts : opt_parser().get());
}

bool
Config::parse_config_file(path file, Options *opts)
{
  bool slash = std::ranges::distance(file.begin(), file.end()) > 1;
  bool fromcwd = slash && !parsing_config_file_;

  if (struct stat sb;
      !slash && file.extension() != ".conf" &&
      fstatat(home_jai(), file.c_str(), &sb, 0) && errno == ENOENT &&
      !fstatat(home_jai(), cat(file, ".conf").c_str(), &sb, 0) &&
      S_ISREG(sb.st_mode))
    file += ".conf";

  Fd fd = openat(fromcwd ? AT_FDCWD : home_jai(), file.c_str(), O_RDONLY);
  if (!fd) {
    if (errno == ENOENT)
      return false;
    syserr("{}", file.c_str());
  }
  parse_config_fd(*fd, opts);
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
  homepath_ = path("/");
  homepath_ /= pw->pw_dir;
  shell_ = pw->pw_shell;
  untrusted_cred_ = user_cred_ = Credentials::get_user(pw);

  setenv("JAI_USER", user_.c_str(), 1);
  // HOME may incorrectly be root's when using su/sudo
  if (realuid == 0 && pw->pw_uid != 0)
    setenv("HOME", pw->pw_dir, 1);

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
  homejaipath_ = homepath_ / (jcd ? jcd : ".jai");
  setenv("JAI_CONFIG_DIR", homejaipath_.c_str(), 1);

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
Config::check_user(const struct stat &sb, std::string p, bool untrusted_ok)
{
  if (sb.st_uid != user_cred_.uid_) {
    if (!untrusted_ok)
      err("{}: owned by {} should be owned by {}", p, sb.st_uid,
          user_cred_.uid_);
    else if (sb.st_uid != untrusted_cred_.uid_)
      err("{}: owned by {} should be owned by {} or {}", p, sb.st_uid,
          user_cred_.uid_, untrusted_cred_.uid_);
  }
}

int
Config::home_jai(bool create)
{
  if (!home_jai_fd_) {
    if (create)
      home_jai_fd_ = ensure_udir(home(), homejaipath_);
    else if (Fd fd = openat(home(), homejaipath_.c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC)) {
      check_user(*fd);
      home_jai_fd_ = std::move(fd);
    }
    else if (errno == ENOENT) {
      err("{} does not exist; run {} --init to create it",
          fdpath(home(), homejaipath_), prog.filename().string());
    }
    else
      syserr("{}", fdpath(home(), homejaipath_));
  }
  return *home_jai_fd_;
}

int
Config::storage()
{
  if (storage_fd_)
    return *storage_fd_;

  auto restore = asuser();

  if (storagedir_.empty())
    storage_fd_ = xdup(home_jai());
  else
    storage_fd_ = ensure_udir(AT_FDCWD, storagedir_);

  path fullpath = fdpath(*storage_fd_, true);
  if (fullpath.is_relative())
    err("cannot find full pathname for {}", storagedir_.string());
  if (!is_fd_at_path(*storage_fd_, -1, fullpath))
    err("{} is no longer at {}", storagedir_.string(), fullpath.string());
  storagedir_ = fullpath;

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

  // Create with permission 0 until we have set propagation mode to
  // private, so we don't accidentally mount things into sandboxes.
  xmnt_move(*make_tmpfs("run-jai", "size", "64M", "mode", "0", "gid", "0"),
            *ensure_dir(-1, kRunRoot, 0, kFollow));

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

  using namespace acl;
  ACL want = normalize({owner("rwx"), uid(user_cred_.uid_, "r-x")});
  if (auto oa = fdgetacl(*dirfd); !oa || *oa != want)
    fdsetacl(*dirfd, want);

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

void
Config::init_jail(int newhomefd)
{
  if (jailinit_.empty())
    return;
  if (access(jailinit_.c_str(), X_OK))
    syserr("{}", jailinit_.string());
  if (auto pid = xfork()) {
    int status;
    while (waitpid(pid, &status, 0) == -1)
      if (errno != EINTR)
        syserr("jailinit waitpid");
    if (WIFEXITED(status)) {
      if (auto val = WEXITSTATUS(status))
        warn("{}: exit code {}{}", jailinit_.string(), val,
             val == 199 ? " (probably couldn't execute)" : "");
    }
    else if (WIFSIGNALED(status))
      warn("{}: killed by signal {}", jailinit_.string(), WTERMSIG(status));
    return;
  }

  try {
    if (fchdir(newhomefd))
      syserr("{}", fdpath(newhomefd));
    user_cred_.make_real();
    umask(old_umask_);
    execl(jailinit_.c_str(), jailinit_.c_str(), nullptr);
    syserr("{}", jailinit_.string());
  } catch (const std::exception &e) {
    warn("{}", e.what());
    _exit(199);
  }
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
  bool need_init =
      faccessat(storage(), chgpath.c_str(), 0, 0) && errno == ENOENT;
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
  sandboxed_home =
      xopenat(run_jai_user(), sb, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
  if (need_init)
    init_jail(*sandboxed_home);
  return sandboxed_home;
}

Fd
Config::make_private_tmproot()
{
  auto r = lock_or_validate_file(
      run_jai_user(), "tmp", O_RDONLY | O_DIRECTORY,
      [](int fd) { return is_mountpoint(fd); }, ".lock");
  if (r)
    return std::move(*r);

  Fd tmp = ensure_dir(run_jai_user(), "tmp", 0755, kFollow);
  if (!is_mountpoint(*tmp)) {
    xmnt_move(*make_tmpfs("jai-tmp", "gid", "0", "mode", "0755", "size", "40%",
                          "huge", "within_size"),
              *tmp);
  }
  return xopenat(run_jai_user(), "tmp", O_RDONLY | O_NOFOLLOW);
}

Fd
Config::make_private_tmp(path subdir, bool userowned)
{
  Fd fd = make_private_tmproot();
  if (!subdir.empty()) {
    assert(subdir.is_relative());
    fd = ensure_dir(*fd, subdir, 0755, kNoFollow, false);
  }

  if (userowned) {
    fd = ensure_dir(*fd, sandbox_name_, 0700, kNoFollow, true, [this](int fd) {
      if (fchown(fd, user_cred_.uid_, user_cred_.gid_))
        syserr("{}: fchown", fdpath(fd));
    });
    check_user(*fd);
    return fd;
  }
  else
    return ensure_dir(*fd, sandbox_name_, 01777, kNoFollow);
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

path
Config::make_script()
{
  if (script_inputs_.empty())
    return {};

  auto restore = asuser();
  Fd dir = xopenat(run_jai_user(), "tmp" / sandbox_name_, O_PATH | O_CLOEXEC);

  Fd w = xopenat(*dir, ".", O_TMPFILE | O_WRONLY | O_CLOEXEC, 0400);
  auto dowrite = [&w](std::string_view sv) {
    auto *p = sv.data(), *e = p + sv.size();
    while (p < e)
      if (auto n = write(*w, p, e - p); n > 0)
        p += n;
      else {
        assert(n == -1);
        syserr("write scriptfile");
      }
  };

  for (const auto &input : script_inputs_) {
    dowrite(read_file(-1, input));
    dowrite("\n");
  }
  dowrite(R"(
# Remove $JAI_SCRIPT once sourced unless JAI_KEEP_SCRIPT is set
if [[ -n $JAI_SCRIPT && -z ${JAI_KEEP_SCRIPT+set} ]]; then
    rm -f "$JAI_SCRIPT"
    unset JAI_SCRIPT
fi
)");

  for (;;) {
    std::array<unsigned char, 10> rndbuf;
    errno = EAGAIN;
    if (getrandom(rndbuf.data(), rndbuf.size(), 0) != rndbuf.size())
      syserr("getrandom");
    path fname = ".jairc";
    for (auto i : rndbuf)
      fname +=
          "+0123456789=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
              [i & 0x3f];

    if (linkat(*w, "", *dir, fname.c_str(), AT_EMPTY_PATH) == 0)
      return "/tmp" / fname;
    else if (errno != EEXIST)
      syserr("{}/{}", fdpath(*dir), fname.c_str());
  }
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

  assert(!sandbox_name_.empty());

  mount_attr attr{
      .attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
      .propagation = MS_PRIVATE,
  };
  Fd tmp = clone_tree(*mp_holder_.emplace_back(make_private_tmp()));

  Fd passwd;
  if (mode_ == kStrict)
    passwd = clone_tree(*make_private_passwd());
  path xdgrun = std::format("/run/user/{}", user_cred_.uid_);
  Fd rundir = grant_directories_.contains(xdgrun)
                  ? Fd{}
                  : clone_tree(*make_private_tmp(".run", true));
  Fd shmdir;
  if (struct stat sb; !stat("/dev/shm", &sb) && S_ISDIR(sb.st_mode))
    shmdir = clone_tree(*make_private_tmp(".shm"));

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
    home = clone_tree(*ensure_udir(storage(), cat(sandbox_name_, ".home"), 0700,
                                   kFollow, [this](int fd) { init_jail(fd); }));
  }
  for (int dfd : {*tmp, *home, *passwd, *rundir, *shmdir})
    if (dfd != -1)
      xmnt_setattr(dfd, attr);

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
  if (rundir)
    xmnt_move(*rundir, -1, xdgrun);
  if (shmdir) {
    umount2("/dev/shm", MNT_DETACH);
    xmnt_move(*shmdir, -1, "/dev/shm");
  }

  if (grant_cwd_) {
    if (!grant_directories_.contains(cwd())) {
      if (cwd() == homepath_) {
        std::string name = prog.filename().string();
        warn(
            R"(Refusing to grant your entire home directory to jailed code.
{1:>{2}}  Run "jai -D" to avoid granting the current working directory.)",
            name, "", name.size());
        exit(1);
      }
      grant_directories_.emplace(cwd(), 0);
    }
  }

  for (const auto &df : grant_directories_) {
    path d = df.first;
    auto flags = df.second;
    if (d.is_relative())
      d = "/" / d;
    if (contains(homejaipath_, d))
      err("{}: cannot export a directory within {}", d.string(),
          homejaipath_.string());
    if (contains(storagedir_, d))
      err("{}: cannot export a directory within {}", d.string(),
          storagedir_.string());
    xsetns(*oldns, CLONE_NEWNS);
    auto restore_root = asuser();
    Fd src =
        flags & kGrantMkdir
            ? ensure_dir(-1, d, 0777 & ~old_umask_, kFollow, false, create_warn)
            : xopenat(-1, d, O_DIRECTORY | O_PATH | O_CLOEXEC);
    check_user(*src, d);
    restore_root.reset();
    src = clone_tree(*src); // Should it be recursive?
    auto dirattr = attr;
    if (flags & kGrantRO)
      dirattr.attr_set |= MOUNT_ATTR_RDONLY;
    xmnt_setattr(*src, dirattr);

    xsetns(*newns, CLONE_NEWNS);
    restore_root = asuser();
    Fd dst = openat(-1, d.c_str(), O_DIRECTORY | O_PATH | O_CLOEXEC);
    if (!dst) {
      if (errno != EACCES && errno != ENOENT)
        syserr("{}", d.string());
      restore_root.reset();
      restore_root = asuser(sbcred);
      dst = ensure_dir(-1, d, 0755, kNoFollow, true);
    }
    check_user(*dst, d, true);
    restore_root.reset();
    xmnt_move(*src, *dst);
  }

  xsetns(*newns, CLONE_NEWNS);

  auto blockdir = [this, &oldns, &newns, &sbcred](const path &p) {
    assert(p.is_absolute());
    auto restore_root = asuser(sbcred);
    Fd target = openat(AT_FDCWD, p.c_str(), O_DIRECTORY | O_RDONLY);
    if (!target)
      return;
    restore_root.reset();

    if (mode_ != kCasual) {
      struct stat sbold, sbnew = xfstat(*target);
      xsetns(*oldns, CLONE_NEWNS);
      int staterr = stat(p.c_str(), &sbold);
      xsetns(*newns, CLONE_NEWNS);
      if (staterr || sbold.st_ino != sbnew.st_ino ||
          sbold.st_dev != sbnew.st_dev)
        return;
    }

    check_user(*target, p, true);
    Fd empty = xopenat(-1, kRunRoot, O_RDONLY);
    if (!is_dir_empty(*empty))
      err("{} should be empty in jail", kRunRoot);
    Fd source = clone_tree(*empty);
    xmnt_setattr(*source, mount_attr{
                              .attr_set = MOUNT_ATTR_RDONLY |
                                          MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
                              .propagation = MS_PRIVATE,
                          });
    xmnt_move(*source, *target);
  };
  blockdir(storagedir_);
  if (homejaipath_ != storagedir_)
    blockdir(homejaipath_);

  return newns;
}

static void
clean_root_owned_dir(int dfd, path file)
{
  assert(components(file) == 1);
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
Config::clean_overlay_work(int dfd, path fname)
{
  Defer restore;
  if (auto uid = geteuid()) {
    restore = [uid] { seteuid(uid); };
    seteuid(0);
  }

  auto d = xopendir(dfd, fname, kFollow);
  check_user(dirfd(d));
  while (auto de = readdir(d)) {
    if (std::string_view name(d_name(de)); name == "." || name == "..")
      continue;
    if (struct stat sb;
        fstatat(dirfd(d), d_name(de), &sb, AT_SYMLINK_NOFOLLOW) ||
        !S_ISDIR(sb.st_mode) || sb.st_uid != 0)
      continue;
    clean_root_owned_dir(dirfd(d), d_name(de));
  }
}

int
Config::unmount()
{
  int ret = 0;
  Fd lock;
  while (!(lock = open_lockfile(run_jai_user(), ".lock")))
    ;

  auto runuser = path(kRunRoot) / user_;

  if (mode_ == kCasual) {
    auto mp = runuser / cat(sandbox_name_, ".home");
    umount2(mp.c_str(), UMOUNT_NOFOLLOW);
    if (unlinkat(run_jai_user(), mp.filename().c_str(), AT_REMOVEDIR) &&
        errno != ENOENT)
      ret = 1;
    if (!ret)
      try {
        clean_overlay_work(storage(), cat(sandbox_name_, ".changes") / ".." /
                                          cat(sandbox_name_, ".work"));
      } catch (const std::exception &e) {
        warn("{}", e.what());
      }
  }
  if (mode_ == kStrict) {
    auto mp = runuser / "passwd";
    if (umount2(mp.c_str(), UMOUNT_NOFOLLOW) && errno != ENOENT)
      ret = 1;
    if (unlinkat(run_jai_user(), mp.filename().c_str(), 0) && errno != ENOENT)
      ret = 1;
  }

  unlinkat(run_jai_user(), ".lock", 0);
  lock.reset();
  unlinkat(run_jai(), user_.c_str(), AT_REMOVEDIR);
  return ret;
}

int
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

            clean_overlay_work(dirfd(jd), workpath);
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

  return unmount_ok ? 0 : 1;
}

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

  auto env_view =
      setenv_ | std::views::values | std::views::transform(&std::string::c_str);
  std::vector<const char *> ret(env_view.begin(), env_view.end());
  ret.push_back(nullptr);
  return ret;
}

static pid_t main_pid = getpid();

// Return stop signal if status indicates a child stopped, exit or
// kill ourselves if the child terminated on a signal, and return 0
// otherwise.
template<typename AtExit = void (*)()>
static int
propagate_termination_status(int status, AtExit &&atexit = +[] {})
{
  if (WIFSTOPPED(status)) {
    if (int sig = WSTOPSIG(status);
        sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU)
      return sig;
    // Unlikely to reach here, but maybe another process attached to
    // our child with the debugger and it got SIGTRAP or something?
    return 0;
  }

  auto do_exit = [&atexit](int status) {
    atexit();
    (getpid() == main_pid ? exit : _exit)(status);
  };

  if (WIFEXITED(status))
    do_exit(WEXITSTATUS(status));
  if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    signal(sig, SIG_DFL);
    auto ss = sigsingleton(WTERMSIG(status));
    sigprocmask(SIG_UNBLOCK, &ss, nullptr);
    raise(sig);
    do_exit(-1);
  }

  return 0; // Continued?
}

static int
wait_propagate(int pid, auto &&atexit)
{
  assert(pid > 0);
  int status;

  for (;;) {
    if (auto r = waitpid(-1, &status, WUNTRACED); r == -1) {
      if (errno != EINTR) {
        atexit();
        if (getpid() == main_pid)
          syserr("waitpid");
        warn("waitpid: {}", strerror(errno));
        _exit(1);
      }
    }
    else if (r == pid)
      if (auto sig = propagate_termination_status(status, atexit); sig > 0)
        return sig;
  }
}

void
Config::fix_proc()
{
  xmnt_propagate(-1, "/", MS_PRIVATE);
  recursive_umount("/proc");
  xmnt_move(*make_mount(*xfsopen("proc", "proc"), MOUNT_ATTR_NOSUID |
                                                      MOUNT_ATTR_NODEV |
                                                      MOUNT_ATTR_NOEXEC),
            -1, "/proc");
}

void
Config::exec(int nsfd, char **argv)
{
  // This function is a bit annoying because the existing jai process
  // cannot move to a new PID namespace, so we have to fork once.  But
  // the forked process will have PID 1 and behave strangely (such as
  // not receiving signals from within the PID namespace), so needs to
  // fork again to run the actual jailed program with a normal PID.
  // That means PID 1 has to propagate termination events of process 2
  // to its own parent, which must then propagate them to the process
  // than ran jai.
  //
  // Further complicating matters, PID 1 cannot stop itself (since it
  // cannot receive a SIGSTOP from within the PID namespace).  Hence,
  // if the jailed program stops, it uses a pipe to request that the
  // original jai process stop it (from outside the PID namespace).
  auto stop_me = xpipe();

  if (auto pid = xfork(CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS)) {
    // This is the last process in the old PID namespace
    close(nsfd);
    stop_me[1].reset();
    // discard first write, whose only purpose is to test the parent
    // didn't die before the child set PR_SET_PDEATSIG.
    char c;
    read(*stop_me[0], &c, 1);
    parent_loop(pid, *stop_me[0]);
  }

  try {
    stop_me[0].reset();
    auto script_path = make_script();
    xsetns(nsfd, CLONE_NEWNS);
    fix_proc();
    pid1(std::move(stop_me[1]), script_path);
    if (!script_path.empty())
      setenv("JAI_SCRIPT", script_path.c_str(), 1);
    pid2(argv);
  } catch (const std::exception &e) {
    warn("{}", e.what());
    _exit(1);
  }
}

void
Config::parent_loop(pid_t pid, int stop_requests)
{
  auto ss = sigsingleton(SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &ss, nullptr))
    syserr("sigprocmask SIG_BLOCK SIGCHLD");
  Fd sigfd = signalfd(-1, &ss, SFD_CLOEXEC);
  if (!sigfd)
    syserr("signalfd");

  if (int n = fcntl(stop_requests, F_GETFL); n == -1)
    syserr("F_GETFL");
  else if (fcntl(stop_requests, F_SETFL, n | O_NONBLOCK) == -1)
    syserr("F_SETFL O_NONBLOCK");

  // Put stop_requests in static to call drain_pipe from signal handler
  static int rqfd;
  rqfd = stop_requests;
  // Flush pipe returning latest signal request or 0 if none
  constexpr auto drain_pipe = +[] {
    int ret = 0, n;
    unsigned char buf[8];
    while ((n = read(rqfd, buf, sizeof(buf))) > 0)
      ret = buf[n - 1];
    if (n == -1 && errno != EAGAIN && errno != EINTR) {
      static const char msg[] = "read from stop_request pipe failed\n";
      write(2, msg, sizeof(msg) - 1);
      _exit(1);
    }
    return ret;
  };

  // If we've been resumed, discard any previous stop requests
  static volatile sig_atomic_t continued = 0;
  struct sigaction sa{};
  sa.sa_handler = +[](int) {
    drain_pipe();
    continued = 1;
  };
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGCONT, &sa, nullptr))
    syserr("sigaction(SIGCONT)");

  std::array<pollfd, 2> pollfds{pollfd{.fd = stop_requests, .events = POLLIN},
                                pollfd{.fd = *sigfd, .events = POLLIN}};

  for (int my_next_stop_sig = 0;;) {
    if (poll(pollfds.data(), pollfds.size(), -1) < 0) {
      if (errno == EINTR)
        continue;
      syserr("poll");
    }

    for (;;) {
      int status;
      if (auto r = waitpid(pid, &status, WNOHANG | WUNTRACED); r == 0)
        break;
      else if (r == -1) {
        if (errno != EINTR)
          syserr("waitpid");
      }
      else if (auto sig = propagate_termination_status(status); sig > 0) {
        if (my_next_stop_sig > 0)
          sig = std::exchange(my_next_stop_sig, 0);
        continued = 0;
        raise(sig);
        if (continued == 0)
          // If we are in an orphaned process group, the default
          // action of SIGTSTP, SIGTTIN, and SIGTTOU is ignore rather
          // than stop.  While we'd like to propagate the exact stop
          // signal of the jailed process when possible, in this case
          // the only way to stop ourselves is with SIGSTOP.
          raise(SIGSTOP);
      }
    }

    if ((my_next_stop_sig = drain_pipe()) > 0)
      kill(pid, SIGSTOP);
  }
}

// Implement PID 1 in the new namespace.  Only returns for PID 2.
void
Config::pid1(Fd stop_me, path script_path)
{
  // Kill entire sandbox if parent jai process terminates
  prctl(PR_SET_PDEATHSIG, SIGKILL);

  // On the off chance that our parent exited and we got reparented to
  // init (outside the sandbox) before setting PDEATHSIG, try writing
  // one byte to the pipe so that a SIGPIPE kills us.
  if (write(*stop_me, "", 1) != 1)
    err("parent killed before PR_SET_PDEATHSIG");

  std::function<void()> atexit = +[] {};
  if (!script_path.empty())
    atexit = [&script_path, sbold = xfstat(-1, script_path)] {
      struct stat sbnew;
      if (!stat(script_path.c_str(), &sbnew) && sbold.st_ino == sbnew.st_ino &&
          sbold.st_ctime == sbnew.st_ctime)
        unlink(script_path.c_str());
    };

  // Return in pid 2, continue in pid 1
  auto pid = xfork();
  if (!pid)
    return;

  prctl(PR_SET_NAME, "jai-init");

  // Note: getpgid is technically not async-signal-safe, but
  // disassembling glibc shows it doesn't do anything problematic
  // other than maybe change errno (which we save/restore in the
  // handler).  Call getpgid at least once before setting the signal
  // handler to avoid any lazy dynamic linking in the signal handler.
  static pid_t my_pgid, main_child_pid;
  my_pgid = getpgid(0);
  main_child_pid = pid;

  static Fd tty;
  tty = open("/dev/tty", O_RDWR | O_CLOEXEC);

  struct sigaction sa{};
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGTTOU);
  sa.sa_handler = +[](int sig) {
    int saved_errno = errno;
    if (auto pg = getpgid(main_child_pid); pg != my_pgid) {
      if (tty)
        tcsetpgrp(*tty, pg);
      killpg(pg, sig);
    }
    errno = saved_errno;
  };
  if (sigaction(SIGCONT, &sa, nullptr))
    syserr("sigaction(SIGCONT)");

  for (;;) {
    unsigned char sig = wait_propagate(pid, atexit);
    write(*stop_me, &sig, 1);
  }
}

void
Config::pid2(char **argv)
{
  if (mode_ == kCasual || mode_ == kBare)
    user_cred_.make_real();
  else
    untrusted_cred_.make_real();
  if (chdir(cwd().c_str())) {
    if (mode_ == kCasual || grant_cwd_ || errno != ENOENT)
      syserr("chdir({})", cwd().string());
    if (chdir(homepath_.c_str()))
      syserr("chdir({})", homepath_.string());
    warn("No \"{}\" in jail, changed to home directory", cwd().string());
  }
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

  auto env = make_env();

  execvpe(argv0, argv, const_cast<char **>(env.data()));
  perror(argv0);
  _exit(1);
}

std::unique_ptr<Options>
Config::opt_parser(bool dotjail)
{
  auto ret = std::make_unique<Options>();
  Options &opts = *ret;
  opts(
      "-m", "--mode",
      [this](std::string_view m) {
        static const std::map<std::string, Mode, std::less<>> modemap{
            {"casual", kCasual}, {"bare", kBare}, {"strict", kStrict}};
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
      [this](std::string_view arg) {
        path d(expand(arg));
        grant_directories_.emplace(
            canonical(parsing_config_file_ ? homepath_ / d : d), 0);
      },
      "Grant full access to DIR", "DIR");
  opts(
      "--dir!",
      [this](std::string_view arg) {
        path d(expand(arg));
        grant_directories_.emplace(
            weakly_canonical(parsing_config_file_ ? homepath_ / d : d),
            kGrantMkdir);
      },
      "Like --dir, but create DIR if it doesn't exist", "DIR");
  opts(
      "-r", "--rdir",
      [this](std::string_view arg) {
        path d(expand(arg));
        grant_directories_.emplace(
            canonical(parsing_config_file_ ? homepath_ / d : d), kGrantRO);
      },
      "Grant read-only access to DIR", "DIR");
  opts(
      "--rdir?",
      [this](std::string_view arg) {
        path d(expand(arg));
        try {
          grant_directories_.emplace(
              canonical(parsing_config_file_ ? homepath_ / d : d), kGrantRO);
        } catch (const std::exception &) {
        }
      },
      "Like --rdir but ignore the option if DIR does not exist", "DIR");
  opts(
      "-x", "--xdir",
      [this](std::string_view arg) {
        path d(expand(arg));
        grant_directories_.erase(
            canonical(parsing_config_file_ ? homepath_ / d : d));
      },
      "Undo the effects of a previous --dir option", "DIR");
  opts(
      "-D", "--nocwd", [this] { grant_cwd_ = false; },
      "Do not grant access to the current working directory");
  if (!dotjail)
    opts(
        "-j", "--jail",
        [this](path sb) {
          if (!name_ok(sb))
            err<Options::Error>("{}: invalid sandbox name", sb.string());
          sandbox_name_ = sb;
        },
        "Use private or overlay home directory named NAME", "NAME");
  else
    opts("-j", "--jail", [](path) {
      err<Options::Error>("cannot set name from a .jail file or include");
    });
  opts("--conf", [this, opts = ret.get()](std::string_view arg) {
    path file(expand(arg));
    if (!parse_config_file(file, opts))
      err<Options::Error>("{}: configuration file not found", file.string());
  });
  opts("--conf?", [this, opts = ret.get()](std::string_view arg) {
    parse_config_file(expand(arg), opts);
  });
  opts(
      "--script",
      [this](path arg) {
        arg = canonical(parsing_config_file_ ? homejaipath_ / arg : arg);
        if (!std::ranges::contains(script_inputs_, arg))
          script_inputs_.push_back(std::move(arg));
      },
      "Source SCRIPT in bash shell used to launch jail", "SCRIPT");
  opts(
      "--script?",
      [this](path arg) {
        try {
          arg = canonical(parsing_config_file_ ? homejaipath_ / arg : arg);
          if (!std::ranges::contains(script_inputs_, arg))
            script_inputs_.push_back(std::move(arg));
        } catch (const std::exception &) {
        }
      },
      "Like --script but don't fail if SCRIPT does not exist", "SCRIPT");
  opts(
      "--initjail",
      [this](path arg) {
        jailinit_ = canonical(parsing_config_file_ ? homejaipath_ / arg : arg);
        if (access(jailinit_.c_str(), X_OK))
          err<Options::Error>("{}: {}", jailinit_.string(),
                              errno == EACCES ? "no execute permission"
                                              : strerror(errno));
      },
      "Run unjailed PROGRAM to initialize new home directories", "PROGRAM");
  opts(
      "--initjail?",
      [this](path arg) {
        arg = weakly_canonical(parsing_config_file_ ? homejaipath_ / arg : arg);
        if (access(arg.c_str(), X_OK)) {
          if (errno == ENOENT)
            return;
          else
            err<Options::Error>("{}: {}", arg.string(),
                                errno == EACCES ? "no execute permission"
                                                : strerror(errno));
        }
        jailinit_ = arg;
      },
      "Like --initjail, but silently ignore non-existent PROGRAM", "PROGRAM");
  opts(
      "--mask",
      [this](std::string_view arg) {
        path p(expand(arg));
        if (p.is_absolute())
          err<Options::Error>("{}: cannot mask an absolute path", p.string());
        mask_files_.emplace(std::move(p));
      },
      "Erase $HOME/FILE when first creating overlay home", "FILE");
  opts(
      "--unmask",
      [this](std::string_view arg) {
        path p(expand(arg));
        mask_files_.erase(p);
      },
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
        if (auto pos = var.find('='); pos != var.npos) {
          auto var_eq_val = std::format("{}{}", var.substr(0, pos + 1),
                                        expand(var.substr(pos + 1)));
          setenv_.insert_or_assign(var.substr(0, pos), var_eq_val);
        }
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
      R"(Bash command line to execute program, e.g:
source "${JAI_SCRIPT:-/dev/null}"; "$0" "$@")",
      "CMD");
  opts(
      "--storage",
      [this](std::string_view s) {
        auto sd = expand(s);
        if (parsing_config_file_)
          storagedir_ = homepath_ / sd;
        else
          storagedir_ = cwd() / sd;
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
{}
Untrusted user for strict mode: {}

Copyright (C) 2026 David Mazieres
This program comes with NO WARRANTY, to the extent permitted by law.
You may redistribute it under the terms of the GNU General Public License
version 3 or later; see the file named COPYING for details.)",
               PACKAGE_STRING, PACKAGE_URL, kUntrustedUser);
  exit(0);
}

int
do_main(int argc, char **argv)
{
  Config conf;
  conf.init_credentials();
  auto restore = conf.asuser();

  // Compute and cache pwd while privileges lowered.  Also override
  // the existing environment variable in case the user does something
  // strange.
  setenv("PWD", conf.cwd().c_str(), 1);

  bool opt_u{};
  std::vector<path> opt_d;
  path opt_C = "";
  bool opt_C_optional{};
  bool opt_init{};

  auto opts = conf.opt_parser();
  // A few options not available in config files
  (*opts)("-u", [&] { opt_u = true; }, "Unmount sandboxed file systems");
  (*opts)(
      "--init", [&] { opt_init = true; },
      "Create initial configuration files and exit");
  // Override inline conf to make CLI idempotent
  (*opts)(
      "-C", "--conf",
      [&](path p) {
        opt_C = p;
        opt_C_optional = false;
      },
      R"(Use FILE as configuration file.  A file FILE with no '/'
is relative to $JAI_CONFIG_DIR if set, otherwise to ~/.jai.
The default is CMD.conf if it exists, otherwise default.conf)",
      "FILE");
  (*opts)(
      "--conf?",
      [&](path p) {
        opt_C = p;
        opt_C_optional = true;
      },
      R"(Like --conf, but no error if the file does not exist)", "FILE");
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

  if (argc > 2 && !strcmp(argv[1], "--complete"))
    return conf.complete(opts->complete_args(2, argc, argv));

  std::vector<char *> cmd;
  try {
    auto parsed = opts->parse_argv(argc, argv);
    cmd.assign(parsed.begin(), parsed.end());
  } catch (Options::Error &e) {
    warn("{}", e.what());
    usage(2);
  }
  if (!conf.mask_files_.empty())
    conf.mask_warn_ = true;

  // true instead of opt_init, just so it works by default.
  ensure_file(conf.home_jai(true), ".defaults", jai_defaults, 0600,
              create_warn);
  ensure_file(conf.home_jai(), "default.conf", default_conf, 0600, create_warn);
  ensure_file(conf.home_jai(), ".jairc", default_jairc, 0600, create_warn);

  if (opt_init) {
    ensure_file(conf.storage(), "default.jail", default_jail, 0600,
                create_warn);
    std::println("You can edit the configuration defaults in {}/.defaults.",
                 conf.homejaipath_.string());
    std::println(
        "Run {} --print-defaults to see the original contents of that file.",
        prog.filename().string());
    return 0;
  }

  if (opt_u &&
      (!conf.grant_cwd_ || !conf.grant_directories_.empty() || !cmd.empty())) {
    std::println(stderr, "-u is not compatible with -d, -D, or a command");
    usage(2);
  }

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

  bool createwarn = false;

  if (conf.sandbox_name_.empty()) {
    if (opt_u) {
      restore.reset();
      return conf.unmountall();
    }
    conf.sandbox_name_ = "default";
  }
  Fd dotjail = ensure_file(conf.storage(), cat(conf.sandbox_name_, ".jail"),
                           conf.sandbox_name_ == "default"
                               ? default_jail
                               : std::format("mode {}\n", conf.mode_),
                           0600, create_warn);
  conf.parse_config_fd(*dotjail, conf.opt_parser(true).get());

  // Re-parse command line to override files
  opts->parse_argv(argc, argv);

  setenv("JAI_JAIL", conf.sandbox_name_.c_str(), 1);
  setenv("JAI_MODE", std::format("{}", conf.mode_).c_str(), 1);

  restore.reset();

  if (opt_u)
    return conf.unmount();

  if (geteuid() && !getenv("JAI_TRY_NONROOT"))
    err("{} requires root. Please run it with sudo or make it setuid root",
        prog.filename().string());

  if (cmd.empty()) {
    const char *shell = conf.shell_.empty() ? "/bin/sh" : conf.shell_.c_str();
    cmd.push_back(const_cast<char *>(shell));
  }

  auto fd = conf.make_mnt_ns();
  cmd.push_back(nullptr);
  conf.exec(*fd, cmd.data());
  return 0;
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
    exit(do_main(argc, argv));
  } catch (const ToCatch &e) {
    warn("{}", e.what());
  }
  return 1;
}
