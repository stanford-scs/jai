// -*-C++-*-

#pragma once

#include "defer.h"
#include "err.h"

#include <algorithm>
#include <cassert>
#include <expected>
#include <filesystem>
#include <format>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <string>
#include <string_view>

#include <dirent.h>
#include <fcntl.h>
#include <linux/posix_acl.h>
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

inline size_t
components(const path &p)
{
  return std::ranges::distance(p.begin(), p.end());
}

inline bool
contains(const path &dir, const path &subpath)
{
  return std::ranges::mismatch(dir, subpath).in1 == dir.end();
}

// True if target matches pattern (with * expanded)
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
template<typename V> using PathMap = std::map<path, V, PathLess>;

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

std::string fdpath(int fd, const path &file);

inline std::string
fdpath(int fd, std::same_as<bool> auto must)
{
  extern std::string do_fdpath_must(int fd, bool must);
  return do_fdpath_must(fd, must);
}
inline std::string
fdpath(int fd)
{
  return fdpath(fd, false);
}

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

inline void
xmnt_propagate(int fd, std::uint64_t propagation, bool recursive = true)
{
  mount_attr a{.propagation = propagation};
  xmnt_setattr(fd, a, recursive ? AT_RECURSIVE : 0);
}

inline void
xmnt_propagate(int fd, path file, std::uint64_t propagation,
               bool recursive = true)
{
  mount_attr a{.propagation = propagation};
  xmnt_setattr(fd, file, a, recursive ? AT_RECURSIVE : 0);
}

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

Fd ensure_dir(
    int dfd, const path &p, mode_t perm, FollowLinks follow,
    bool okay_if_other_owner = false,
    std::function<void(int)> createcb = [](int) {});

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
xopenat(int dfd, const path &file, int flags, mode_t mode = 0644)
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

inline std::expected<RaiiHelper<closedir>, std::system_error>
try_opendir(int dfd, path file = {}, FollowLinks follow = kNoFollow)
{
  if (file.empty())
    // re-open in case dfd is O_PATH and to avoid messing with the
    // offset of dfd if we read the directory multiple times
    file = ".";
  Fd fd = openat(dfd, file.c_str(),
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                     (follow == kNoFollow ? O_NOFOLLOW : 0));
  if (!fd)
    return std::unexpected{
        std::system_error(errno, std::system_category(), fdpath(dfd, file))};

  if (auto d = fdopendir(*fd)) {
    fd.release();
    return d;
  }
  return std::unexpected{
      std::system_error(errno, std::system_category(),
                        std::format("{}: fdopendir", fdpath(*fd)))};
}

inline RaiiHelper<closedir>
xopendir(int dfd, path file = {}, FollowLinks follow = kNoFollow)
{
  if (auto r = try_opendir(dfd, file, follow))
    return std::move(*r);
  else
    throw r.error();
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

std::string read_fd(int fd);

// This tries to read a file.  It will return an error if the file
// cannot be opened (e.g., because it does not exist), but could still
// throw if reading the actual file returns an error or allocating the
// buffer exhausts memory.
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

inline void
create_warn(int fd)
{
  warn("created {}", fdpath(fd));
}

Fd ensure_file(
    int dfd, path file, std::string_view contents, int mode = 0600,
    std::function<void(int)> createcb = [](int) {});

using XattrVal = std::vector<std::byte>;

std::optional<XattrVal> xfgetxattr(int fd, const char *attrname,
                                   size_t initial_size = 64);

void xfsetxattr(int fd, const char *attrname, std::span<const std::byte> val,
                int flags = 0);

namespace acl {

struct Perm {
  uint16_t val{};
  constexpr Perm(int v) : val(v) {}
  consteval Perm(const char *s)
  {
    while (*s)
      switch (*s++) {
      case 'r':
        val |= ACL_READ;
        break;
      case 'w':
        val |= ACL_WRITE;
        break;
      case 'x':
        val |= ACL_EXECUTE;
        break;
      case '-':
        break;
      default:
        throw "invalid permission string";
      }
  }
};

struct Entry {
  uint16_t tag;
  uint16_t perm;
  uint32_t id = ACL_UNDEFINED_ID;

  constexpr Entry(uint16_t t, Perm p) noexcept : tag(t), perm(p.val) {}
  constexpr Entry(uint16_t t, uint32_t i, Perm p) noexcept
    : tag(t), perm(p.val), id(i)
  {
    assert(has_id() || id == ACL_UNDEFINED_ID);
  }

  static constexpr char tag_char(uint16_t tag)
  {
    switch (tag) {
    case ACL_USER_OBJ:
    case ACL_USER:
      return 'u';
    case ACL_GROUP_OBJ:
    case ACL_GROUP:
      return 'g';
    case ACL_MASK:
      return 'm';
    case ACL_OTHER:
      return 'o';
    default:
      return 0;
    }
  }
  char tag_char() const { return tag_char(tag); }

  static constexpr bool has_id(uint16_t tag)
  {
    return tag == ACL_USER || tag == ACL_GROUP;
  }
  bool has_id() const { return has_id(tag); }

  template<uint16_t Tag> requires (has_id(Tag))
  static Entry make(uint32_t i, Perm p)
  {
    return {Tag, i, p};
  }
  template<uint16_t Tag> requires (!has_id(Tag))
  static Entry make(Perm p)
  {
    return {Tag, p};
  }

  friend auto operator<=>(const Entry &, const Entry &) noexcept = default;
};

constexpr auto owner = Entry::make<ACL_USER_OBJ>;
constexpr auto fgroup = Entry::make<ACL_GROUP_OBJ>; // "file group"
constexpr auto other = Entry::make<ACL_OTHER>;
constexpr auto uid = Entry::make<ACL_USER>;
constexpr auto gid = Entry::make<ACL_GROUP>;
constexpr auto mask = Entry::make<ACL_MASK>;

using ACL = std::vector<Entry>;

XattrVal serialize(const ACL &a);
ACL deserialize(const XattrVal &raw);

struct AclName {
  const char *const name;
  consteval explicit AclName(const char *n) : name(n) {}
};
// ACL on an inode
constexpr AclName kAclAccess("system.posix_acl_access");
// ACL for newly created files in a directory
constexpr AclName kAclDefault("system.posix_acl_default");

std::optional<ACL> fdgetacl(int fd, AclName which = kAclAccess);
void fdsetacl(int fd, const ACL &val, AclName which = kAclAccess,
              int flags = 0);

// Remove duplicate entries (last one wins), make sure owner, fgroup,
// other, and mask are present.
ACL normalize(const ACL &a);

} // namespace acl

template<> struct std::formatter<acl::Entry> {
  using entry_type = acl::Entry;
  constexpr auto parse(auto &ctx) { return ctx.begin(); }
  auto format(const entry_type &e, auto &ctx) const
  {
    auto out = ctx.out();
    if (char c = e.tag_char())
      out = std::format_to(out, "{}:", c);
    else
      out = std::format_to(out, "TAG#{}:", e.tag);
    if (e.has_id())
      out = std::format_to(out, "{}", e.id);
    else if (e.id != ACL_UNDEFINED_ID)
      out = std::format_to(out, "[{}]", e.id);
    return std::format_to(out, ":{}{}{}", e.perm & ACL_READ ? 'r' : '-',
                          e.perm & ACL_WRITE ? 'w' : '-',
                          e.perm & ACL_EXECUTE ? 'x' : '-');
  }
};

template<> struct std::formatter<acl::ACL> : std::formatter<std::string> {
  using super = std::formatter<std::string>;
  auto format(const acl::ACL &a, auto &ctx) const
  {
    std::string buf;
    for (const auto &e : a) {
      if (!buf.empty())
        buf += ',';
      buf += std::format("{}", e);
    }
    return std::format_to(ctx.out(), "{}", buf);
  }
};
