// -*-C++-*-

#pragma once

#include "defer.h"
#include "err.h"

#include <algorithm>
#include <expected>
#include <filesystem>
#include <ranges>
#include <set>
#include <string>
#include <string_view>

#include <dirent.h>
#include <fcntl.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

// Self-closing file descriptor
using Fd = RaiiHelper<::close, int, -1>;

using std::filesystem::path;

inline path
cat(path left, const path &right)
{
  return left += right;
}

// True is target matches pattern (with * expanded)
bool glob(std::string_view pattern, std::string_view target);

// Compare paths component by component so subtrees are contiguous
struct PathLess {
  static bool operator()(const path &a, const path &b)
  {
    return std::ranges::lexicographical_compare(a, b);
  }
};

using PathSet = std::set<path, PathLess>;
using PathMultiset = std::multiset<path, PathLess>;

// Return a range for a subtree rooted at root.  root itself will be
// returned only if it does not contain a trailing slash.
inline auto
subtree(const is_one_of<PathSet, PathMultiset> auto &s, const path &root)
{
  if (root.relative_path().empty())
    return std::ranges::subrange(s.begin(), s.end());
  path end = root;
  if (end.filename().empty())
    end = end.parent_path();
  // First possible pathname not under root is the (illegal) pathname
  // in which root's final component has a '\0' byte appended.
  end += '\0';
  return std::ranges::subrange(s.lower_bound(root), s.lower_bound(end));
}

// Return a subtree in reverse order (suitable for unmounting).
inline auto
subtree_rev(const is_one_of<PathSet, PathMultiset> auto &s, const path &root)
{
  return subtree(s, root) | std::views::reverse;
}

std::string fdpath(int fd, const path &file, bool must = false);
std::string fdpath(int fd, bool must = false);

PathMultiset mountpoints(const path &mountinfo = "/proc/self/mountinfo");

// source (if non-NULL) is the source printed in /proc/self/mountinfo
Fd xfsopen(const char *fsname, const char *source = nullptr);

// Calls fsconfig(FSCONFIG_CMD_CREATE) and fsmount.
Fd make_mount(int conffd, int attr = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV);

Fd clone_tree(int dfd, const path &file = {}, bool recursive = false);

void xmnt_move(int fromfd, const path &frompath, int tofd, const path &topath,
               int flags);
inline void
xmnt_move(int fromfd, int tofd, const path &topath = {}, int flags = 0)
{
  xmnt_move(fromfd, path{}, tofd, topath, flags);
}

void xmnt_setattr(int fd, const path &file, const mount_attr &a,
                  unsigned int flags = AT_RECURSIVE);
inline void
xmnt_setattr(int fd, const mount_attr &a, unsigned int flags = AT_RECURSIVE)
{
  xmnt_setattr(fd, {}, a, flags);
}

void xmnt_propagate(int fd, std::uint64_t propagation, bool recursive = true);

template<std::convertible_to<const char *>... Opt>
requires (sizeof...(Opt) % 2 == 0)
Fd
make_tmpfs(const char *source, Opt... opt)
{
  Fd conf = xfsopen("tmpfs", source);
  if constexpr (sizeof...(Opt)) {
    auto options = std::to_array<const char *>({opt...});
    for (auto i = 0uz; i < options.size() - 1; i += 2)
      if (fsconfig(*conf, FSCONFIG_SET_STRING, options[i], options[i + 1], 0))
        syserr(R"(fsconfig(tmpfs, "{}", "{}"))", options[i], options[i + 1]);
  }
  return make_mount(*conf);
}

bool recursive_umount(const path &tree, bool detach = true);

enum class FollowLinks {
  kNoFollow = 0,
  kFollow = 1,
};
using enum FollowLinks;

// Conservatively fails if file is not a regular file or cannot be
// statted for any reason.
bool is_fd_at_path(int targetfd, int dfd, const path &file,
                   FollowLinks follow = kNoFollow,
                   struct stat *sbout = nullptr);

bool is_dir_empty(int dirfd);

Fd ensure_dir(int dfd, const path &p, mode_t perm, FollowLinks follow,
              bool okay_if_other_owner = false);

void make_whiteout(int dfd, const path &p);

bool is_mountpoint(int dfd, const path &file = {},
                   FollowLinks follow = kNoFollow);

// Open an exclusive lockfile to guard one-time setup.  Might fail, in
// which case re-check the need for setup and try again.
Fd open_lockfile(int dfd, const path &file);

// If validate(get()) is true, returns the result of get() in the
// expected value.  Otherwise, acquires the lock and returns an error
// value containing a Defer object that releases the lock.
//
// Be careful not to destroy the return value.  This would be bad:
//
//    if (auto r = lock_or_validate(...); r)
//      return std::move(*r);
//    // now you no longer have the lock
//
// Instead you want:
//
//    auto r = lock_or_validate(...);
//    if (r)
//      return std::move(*r);
//    // now you continue to hold the lock until r is destroyed
template<typename Get,
         typename Validate = decltype([](auto &&v) { return bool(v); })>
std::expected<std::decay_t<std::invoke_result_t<Get>>, Defer>
lock_or_validate(int dfd, path lockfile, Get get, Validate validate = {})
    requires requires {
      { validate(get()) } -> std::convertible_to<bool>;
    }
{
  std::expected<std::decay_t<std::invoke_result_t<Get>>, Defer> ret =
      std::unexpected{Defer{}};

  Fd lock;
  for (;;) {
    if (validate(ret.emplace(get())))
      return ret;
    if (lock) {
      ret = std::unexpected{Defer{[lock = std::move(lock), dfd, lockfile] {
        unlinkat(dfd, lockfile.c_str(), 0);
      }}};
      return ret;
    }
    lock = open_lockfile(dfd, lockfile);
  }
}

std::string open_flags_to_string(int flags);

inline Fd
xopenat(int dfd, const path &file, int flags, mode_t mode = 0755)
{
  if (int fd = openat(dfd, file.c_str(), flags, mode); fd >= 0)
    return fd;
  syserr(R"(openat("{}", {}))",
         dfd >= 0 ? (fdpath(dfd) / file).string() : file.string(),
         open_flags_to_string(flags));
}

inline Fd
xdup(int fd, int minfd = 3)
{
  auto ret = fcntl(fd, F_DUPFD_CLOEXEC, minfd);
  if (ret == -1)
    syserr("{}: F_DUPFD_CLOEXEC", fdpath(fd));
  return ret;
}

inline RaiiHelper<closedir>
xopendir(int dfd, path file = {}, FollowLinks follow = kNoFollow)
{
  Fd fd;
  if (file.empty())
    fd = xdup(dfd);
  else
    fd = xopenat(dfd, file,
                 O_RDONLY | O_DIRECTORY |
                     (follow == kNoFollow ? O_NOFOLLOW : 0));
  if (auto d = fdopendir(*fd)) {
    fd.release();
    return d;
  }
  syserr("fdopendir({})", fdpath(dfd, file));
}

// dirent::d_name is an array, so won't convert properly to types that
// treat a char array differently from a const char *.
inline const char *
d_name(const struct dirent *de)
{
  return de->d_name;
}

inline std::array<Fd, 2>
xpipe()
{
  int fds[2];
  if (pipe2(fds, O_CLOEXEC))
    syserr("pipe2");
  return {fds[0], fds[1]};
}

inline struct stat
xfstat(int fd, path file = {}, FollowLinks follow = kFollow)
{
  struct stat sb;
  if (file.empty()) {
    if (fstat(fd, &sb))
      syserr(R"(fstat("{}"))", fdpath(fd));
  }
  else if (fstatat(fd, file.c_str(), &sb,
                   follow == kFollow ? 0 : AT_SYMLINK_NOFOLLOW))
    syserr(R"({}stat("{}"))", follow == kFollow ? "" : "l", fdpath(fd, file));
  return sb;
}

std::expected<std::string, std::system_error> try_read_file(int dfd,
                                                            path file = {});

inline std::string
read_file(int dfd, path file = {})
{
  if (auto res = try_read_file(dfd, file))
    return std::move(*res);
  else
    throw res.error();
}

Fd ensure_file(int dfd, path file, std::string_view contents, int mode = 0600);

using ACL = RaiiHelper<acl_free, acl_t>;

enum AclType {
  kAclAccess = ACL_TYPE_ACCESS,   // Set ACL on inode
  kAclDefault = ACL_TYPE_DEFAULT, // Set ACL for files created in directory
};
void set_fd_acl(int fd, const char *acltext, AclType which = kAclAccess);
