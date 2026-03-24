#include <cassert>
#include <cstring>
#include <filesystem>

#include <libmount.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "defer.h"
#include "fs.h"

bool
glob(std::string_view pattern, std::string_view target)
{
  if (pattern.empty())
    return target.empty();
  if (pattern.front() == '\\') {
    if ((pattern = pattern.substr(1)).empty())
      return false;
  }
  else if (pattern.front() == '*')
    return glob(pattern.substr(1), target) ||
           (!target.empty() && glob(pattern, target.substr(1)));
  return !target.empty() && pattern.front() == target.front() &&
         glob(pattern.substr(1), target.substr(1));
}

std::string
fdpath(int fd, bool must)
{
  if (fd < 0 || fd == AT_FDCWD) {
    if (must)
      err("fdpath invalid fd {}", fd);
    return ".";
  }
  auto procfd = std::format("/proc/self/fd/{}", fd);
  std::error_code ec;
  auto res = std::filesystem::read_symlink(procfd, ec);
  if (ec) {
    if (must) {
      errno = ec.value();
      syserr("{}", procfd);
    }
    res = std::format("fd {} [can't determine path]", fd, ec.message());
  }
  else if (must && !res.is_absolute() || !is_fd_at_path(fd, -1, res))
    err("{} not valid complete path for fd {}", res.string(), fd);
  return res;
}

std::string
fdpath(int fd, const path &file)
{
  if (fd < 0 || fd == AT_FDCWD || file.is_absolute())
    return file.empty() ? "." : file.string();
  auto procfd = std::format("/proc/self/fd/{}", fd);
  std::error_code ec;
  auto res = std::filesystem::read_symlink(procfd, ec);
  if (ec)
    res = std::format("fd {} [can't determine path]: {}", fd, ec.message());
  if (!file.empty())
    res = res / file;
  return res;
}

PathMultiset
mountpoints(const path &mountinfo)
{
  RaiiHelper<mnt_unref_table> t = mnt_new_table();
  if (!t)
    err("mnt_new_table() failed");
  if (mnt_table_parse_file(t, mountinfo.c_str()))
    syserr("parse {}", mountinfo.string());

  RaiiHelper<mnt_free_iter> i = mnt_new_iter(MNT_ITER_FORWARD);
  if (!i)
    err("mnt_new_iter(MNT_ITER_FORWARD) failed");

  PathMultiset res;
  libmnt_fs *mp = nullptr;
  while (!mnt_table_next_fs(t, i, &mp))
    if (const char *target = mnt_fs_get_target(mp))
      res.emplace(target);
  return res;
}

Fd
xfsopen(const char *fsname, const char *source)
{
  Fd fd = fsopen(fsname, FSOPEN_CLOEXEC);
  if (!fd)
    syserr(R"(fsopen("{}")", fsname);
  if (source && fsconfig(*fd, FSCONFIG_SET_STRING, "source", source, 0))
    syserr(R"(fsconfig({}, FSCONFIG_SET_STRING, "source", "{}", 0))", fsname,
           source);
  return fd;
}

Fd
make_mount(int conffd, int attr)
{
  if (fsconfig(conffd, FSCONFIG_CMD_CREATE, nullptr, nullptr, 0))
    syserr("fsconfig(FSCONFIG_CMD_CREATE)");
  Fd ret = fsmount(conffd, FSMOUNT_CLOEXEC, attr);
  if (!ret)
    syserr("fsmount");
  return ret;
}

Fd
clone_tree(int dfd, const path &file, bool recursive)
{
  int flags =
      AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE;
  if (recursive)
    flags |= AT_RECURSIVE;
  if (Fd ret = open_tree(dfd, file.c_str(), flags))
    return ret;
  syserr(R"(open_tree({}, "{}", 0x{:x}))", fdpath(dfd), file.string(), flags);
}

void
xmnt_move(int fromfd, const path &fromfile, int tofd, const path &tofile,
          int flags)
{
  if (move_mount(fromfd, fromfile.c_str(), tofd, tofile.c_str(),
                 flags | MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH))
    syserr("move_mount({}, {})", fdpath(fromfd), fdpath(tofd, tofile));
}

void
xmnt_setattr(int fd, const path &file, const mount_attr &a, unsigned int flags)
{
  flags |= AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;
  // Why mount_setattr takes a non-const mount_attr I don't understand...
  if (mount_setattr(fd, file.c_str(), flags, const_cast<mount_attr *>(&a),
                    sizeof(a)))
    syserr("mount_setattr({})", fdpath(fd));
}

bool
recursive_umount(const path &tree, bool detach)
{
  bool ret = true;
  auto mps = mountpoints();
  auto dirs = subtree_rev(mps, tree);
  for (const auto &dir : dirs) {
    if (umount2(dir.c_str(), UMOUNT_NOFOLLOW)) {
      warn(R"(umount("{}"): {})", dir.string(), strerror(errno));
      if (detach && umount2(dir.c_str(), UMOUNT_NOFOLLOW | MNT_DETACH) == 0)
        warn("did lazy unmount of {}\n", dir.string());
      else
        ret = false;
    }
  }
  return ret;
}

bool
is_fd_at_path(int targetfd, int dfd, const path &file, FollowLinks follow,
              struct stat *sbout)
{
  struct stat sbtmp, sbpath;
  if (!sbout)
    sbout = &sbtmp;
  if (fstat(targetfd, sbout))
    syserr("fstat({})", fdpath(targetfd));
  if (fstatat(dfd, file.c_str(), &sbpath,
              follow == kFollow ? 0 : AT_SYMLINK_NOFOLLOW))
    return false;
  return sbout->st_dev == sbpath.st_dev && sbout->st_ino == sbpath.st_ino;
}

bool
is_dir_empty(int dirfd)
{
  auto dir = xopendir(dirfd);
  while (auto de = readdir(dir))
    if (de->d_name[0] != '.' ||
        (de->d_name[1] != '\0' &&
         (de->d_name[1] != '.' || de->d_name[2] != '\0')))
      return false;
  return true;
}

Fd
ensure_dir(int dfd, const path &p, mode_t perm, FollowLinks follow,
           bool okay_if_other_owner)
{
  assert(!p.empty());

  Fd fd;
  int flag = follow == kFollow ? 0 : O_NOFOLLOW;
  if (p.is_absolute())
    dfd = *(fd = xopenat(-1, "/", O_RDONLY));
  for (auto component = p.begin(); component != p.end();) {
    if (Fd nfd = openat(dfd, component->c_str(),
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | flag)) {
      dfd = *(fd = std::move(nfd));
      ++component;
    }
    else if (errno != ENOENT)
      syserr(R"(ensure_dir("{}"): open("{}"))", p.string(),
             fdpath(dfd, *component));
    else if (mkdirat(dfd, component->c_str(), perm) && errno != EEXIST)
      syserr(R"(ensure_dir("{}"): mkdir("{}"))", p.string(),
             fdpath(dfd, *component));
    else if (struct stat sb; fstatat(dfd, component->c_str(), &sb, 0))
      syserr(R"(ensure_dir("{}"): stat("{}"))", p.string(),
             fdpath(dfd, *component));
    else if (!S_ISDIR(sb.st_mode)) {
      syserr(R"(ensure_dir("{}"): "{}" is not a directory)", p.string(),
             fdpath(dfd, *component));
    }
    // Don't advance iterator; want to open directory we just created
  }

  auto sb = xfstat(*fd);
  if (!okay_if_other_owner) {
    auto euid = geteuid();
    if (sb.st_uid != euid)
      err("{}: has uid {} should have {}", p.string(), sb.st_uid, euid);
    // Because we run with a weird gid
    if (!euid && sb.st_gid)
      fchown(*fd, -1, 0);
  }
  if (auto m = sb.st_mode & perm; m != (sb.st_mode & 07777) && fchmod(*fd, m))
    syserr(R"(fchmod("{}", {:o}))", p.string(), m);
  return fd;
}

void
make_whiteout(int dfd, const path &inp)
{
  auto p = inp.lexically_normal();
  if (!p.has_filename())
    p = p.parent_path();
  if (p.is_absolute() || p.empty() || *p.begin() == "..")
    err<std::logic_error>(R"(make_whiteout: "{}" is not a relative path)",
                          inp.string());

  try {
    Fd dirholder;
    if (p.has_parent_path()) {
      dirholder = ensure_dir(dfd, p.parent_path(), 0700, kNoFollow, false);
      dfd = *dirholder;
      p = p.filename();
    }

    auto olduid = geteuid();
    seteuid(0);
    int err = 0;
    if (mknodat(dfd, p.filename().c_str(), S_IFCHR, 0))
      err = errno;
    seteuid(olduid);
    if ((errno = err))
      syserr("mknod {}/.jai c 0 0", fdpath(dfd, p));
  } catch (const std::system_error &e) {
    if (e.code() != std::errc::not_a_directory &&
        e.code() != std::errc::file_exists)
      throw;
  }
}

bool
is_mountpoint(int dfd, const path &file, FollowLinks follow)
{
  struct statx stx;
  int flags = AT_EMPTY_PATH | AT_NO_AUTOMOUNT;
  if (follow != kFollow)
    flags |= AT_SYMLINK_NOFOLLOW;
  if (statx(dfd, file.c_str(), flags, STATX_BASIC_STATS, &stx))
    syserr(R"(statx("{}", "{}"))", fdpath(dfd), file.string());
  if (!(stx.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT))
    err("statx does not support STATX_ATTR_MOUNT_ROOT");
  return stx.stx_attributes & STATX_ATTR_MOUNT_ROOT;
}

Fd
open_lockfile(int dfd, const path &file)
{
  assert(!file.empty());

  Fd fd = openat(dfd, file.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd) {
    if (!flock(*fd, LOCK_EX | LOCK_NB)) {
      struct stat sb;
      if (!is_fd_at_path(*fd, dfd, file, kNoFollow, &sb))
        // Someone may have unlinked after completing setup; fail and
        // expect the invoker to call again if setup isn't complete.
        fd.reset();
      else if (!S_ISREG(sb.st_mode))
        err("{}: expected regular file", fdpath(dfd, file));
      return fd;
    }
    if (errno != EWOULDBLOCK && errno != EINTR)
      syserr(R"(flock("{}", LOCK_EX|LOCK_NB))", file.string());
    // We failed, but delay returning until lock is released, at which
    // point setup will likely be complete.
    if (flock(*fd, LOCK_SH) && errno != EINTR)
      syserr(R"(flock("{}", LOCK_SH))", file.string());
    fd.reset();
    return fd;
  }
  if (errno != ENOENT)
    syserr(R"(open("{}"))", file.string());

  path parent = file.parent_path();
  const char *pp = parent.empty() ? "." : parent.c_str();
  fd = xopenat(dfd, pp, O_RDWR | O_TMPFILE | O_CLOEXEC, 0600);
  if (flock(*fd, LOCK_EX | LOCK_NB))
    // It's a temp file so should be impossible for anyone else to lock it
    syserr("flock(O_TMPFILE)");
  if (linkat(*fd, "", dfd, file.c_str(), AT_EMPTY_PATH)) {
    if (errno != EEXIST)
      syserr(R"(linkat("{}"))", file.string());
    fd.reset();
  }
  return fd;
}

std::string
open_flags_to_string(int flags)
{
  struct Flag {
    int bits;
    const char *name;
  };
  static constexpr auto composites = std::to_array<Flag>({
      {O_ACCMODE, "3"},
      {O_SYNC, "O_SYNC"},
      {O_TMPFILE, "O_TMPFILE"},
  });
  static constexpr auto known_flags = std::to_array<Flag>({
      {O_WRONLY, "O_WRONLY"},
      {O_RDWR, "O_RDWR"},
      {O_CREAT, "O_CREAT"},
      {O_EXCL, "O_EXCL"},
      {O_NOCTTY, "O_NOCTTY"},
      {O_TRUNC, "O_TRUNC"},
      {O_APPEND, "O_APPEND"},
      {O_NONBLOCK, "O_NONBLOCK"},
      {O_DSYNC, "O_DSYNC"},
      {O_ASYNC, "O_ASYNC"},
      {O_DIRECT, "O_DIRECT"},
      {O_LARGEFILE, "O_LARGEFILE"},
      {O_DIRECTORY, "O_DIRECTORY"},
      {O_NOFOLLOW, "O_NOFOLLOW"},
      {O_NOATIME, "O_NOATIME"},
      {O_CLOEXEC, "O_CLOEXEC"},
      {O_SYNC, "O_SYNC"},
      {O_PATH, "O_PATH"},
  });

  std::string result;
  auto append = [&](const char *name) {
    result += name;
    result += '|';
  };

  if ((flags & (O_ACCMODE | O_PATH)) == 0)
    append("O_RDONLY");

  for (auto &c : composites)
    if ((flags & c.bits) == c.bits) {
      append(c.name);
      flags &= ~c.bits;
    }

  for (auto &f : known_flags)
    if (flags & f.bits)
      append(f.name);

  if (auto n = result.size())
    result.resize(n - 1);
  return result;
}

void
set_fd_acl(int fd, const char *acltext, AclType which)
{
  ACL acl = acl_from_text(acltext);
  if (!acl)
    syserr(R"(acl_from_text("{}"))", acltext);
  if (acl_valid(acl) != 0)
    syserr(R"(acl_validate("{}"))", acltext);

  if (which == kAclAccess) {
    if (acl_set_fd(fd, acl))
      syserr(R"(acl_set_fd("{}", {}))", fdpath(fd), acltext);
    return;
  }

  auto procfd = std::format("/proc/self/fd/{}", fd);
  if (acl_set_file(procfd.c_str(), ACL_TYPE_DEFAULT, acl))
    syserr(R"(acl_set_file("{}", DEFAULT, {}))", fdpath(fd), acltext);
}

std::string
read_fd(int fd)
{
  std::string ret;
  if (auto sb = xfstat(fd); sb.st_size > 0x100'0000) {
    // Let's not go crazy with sparse files and such
    errno = EFBIG;
    syserr("{}", fdpath(fd));
  }
  else if (sb.st_size > 0)
    ret.reserve(sb.st_size);
  for (;;) {
    char buf[4096];
    auto n = read(fd, buf, sizeof(buf));
    if (n == 0)
      return ret;
    if (n < 0)
      syserr("{}: read", fdpath(fd));
    ret.append(buf, size_t(n));
  }
}

std::expected<std::string, std::system_error>
try_read_file(int dfd, path file)
{
  Fd fdholder;
  int fd = dfd;
  if (!file.empty()) {
    fdholder = openat(fd, file.c_str(), O_RDONLY | O_CLOEXEC);
    if (!fdholder)
      return std::unexpected(
          std::system_error(errno, std::system_category(), fdpath(fd, file)));
    fd = *fdholder;
  }
  return read_fd(fd);
}

Fd
ensure_file(int dfd, path file, std::string_view contents, int mode,
            bool *created)
{
  assert(!file.empty());

  if (Fd fd = openat(dfd, file.c_str(), O_RDONLY | O_CLOEXEC)) {
    if (!S_ISREG(xfstat(*fd).st_mode))
      err("{}: not a regular file", fdpath(dfd, file));
    if (created)
      *created = false;
    return fd;
  }
  if (errno != ENOENT)
    syserr("{}", fdpath(dfd, file));

  path tmp = cat(file, std::format("~{}~", getpid()));
  unlinkat(dfd, tmp.c_str(), 0);
  Defer cleanup{[dfd, &tmp] { unlinkat(dfd, tmp.c_str(), 0); }};

  Fd fd =
      xopenat(dfd, tmp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, mode);
  for (size_t i = 0; i < contents.size();) {
    if (auto n = write(*fd, contents.data() + i, contents.size() - i); n < 0)
      syserr(R"(write(O_TMPFILE for "{}"))", fdpath(dfd, file));
    else
      i += n;
  }
  if (fsync(*fd))
    syserr("fsync(\"{}\")", fdpath(*fd));
  if (renameat(dfd, tmp.c_str(), dfd, file.c_str()))
    syserr(R"(rename("{}" -> "{}") in "{}")", tmp.string(), file.string(),
           fdpath(*fd));
  cleanup.release();
  if (created)
    *created = true;
  fd.reset();                   // have to reopen for reading
  return xopenat(dfd, file.c_str(), O_RDONLY | O_CLOEXEC);
}
