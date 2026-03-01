// -*-C++-*-

#pragma once

#include <algorithm>
#include <concepts>
#include <expected>
#include <filesystem>
#include <format>
#include <functional>
#include <ranges>
#include <set>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

#include <fcntl.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

// Format error message and throw an exception that captures errno
template<typename... Args>
[[noreturn]] inline void
syserr(std::format_string<Args...> fmt, Args &&...args)
{
  throw std::system_error(
      errno, std::system_category(),
      std::vformat(fmt.get(), std::make_format_args(args...)));
}

// Format error message and throw exception
template<typename E = std::runtime_error, typename... Args>
[[noreturn]] inline void
err(std::format_string<Args...> fmt, Args &&...args)
{
  throw E(std::vformat(fmt.get(), std::make_format_args(args...)));
}

template<auto F>
using ArgType =
    decltype([]<typename R, typename A>(R (*)(A)) -> A { throw; }(F));

template<typename T, typename... Ts>
concept is_one_of = (std::same_as<T, Ts> || ...);

// Note that Destroy generally should not throw, whether or not it is
// declared noexcept.  Only an explicit call to reset() will allow
// exceptions to propagate.
template<auto Destroy, typename T = ArgType<Destroy>, auto Empty = T{}>
struct RaiiHelper {
  T t_ = Empty;

  constexpr RaiiHelper() noexcept = default;
  RaiiHelper(T t) noexcept : t_(std::move(t)) {}
  RaiiHelper(RaiiHelper &&other) noexcept : t_(other.release()) {}
  ~RaiiHelper() { reset(); }

  template<is_one_of<T, decltype(Empty)> Arg>
  RaiiHelper &operator=(Arg &&arg) noexcept
  {
    reset(std::forward<Arg>(arg));
    return *this;
  }
  RaiiHelper &operator=(RaiiHelper &&other) noexcept
  {
    return *this = other.release();
  }

  explicit operator bool() const noexcept { return t_ != Empty; }
  decltype(auto) operator*(this auto &&self) noexcept { return (self.t_); }
  auto addr(this auto &&self) noexcept { return std::addressof(self); }

  // For legacy libraries that want a T**, return that type for &
  template<std::same_as<T> U = T> requires std::is_pointer_v<U>
  auto operator&(this auto &&self) noexcept
  {
    return &self.t_;
  }
  // Make it easier to use RaiiHelper with pointers in C libraries
  template<std::same_as<T> U = T> requires std::is_pointer_v<U>
  operator U() const
  {
    return t_;
  }
  decltype(auto) operator->(this auto &&self) noexcept { return (self.t_); }

  T release() noexcept { return std::exchange(t_, Empty); }

  template<is_one_of<T, decltype(Empty)> Arg>
  void reset(Arg &&arg) noexcept(noexcept(Destroy(std::move(t_))))
  {
    if (auto destroy_me = std::exchange(t_, std::forward<Arg>(arg));
        destroy_me != Empty)
      Destroy(std::move(destroy_me));
  }
  void reset() noexcept(noexcept(reset(Empty))) { reset(Empty); }
};

// Self-closing file descriptor
using Fd = RaiiHelper<::close, int, -1>;

namespace detail {
struct NullaryInvoker {
  template<typename F> static decltype(auto) operator()(F &&f)
  {
    return std::forward<F>(f)();
  }
};
} // namespace detail
// Deferred cleanup action
using Defer = RaiiHelper<detail::NullaryInvoker{},
                         std::move_only_function<void()>, nullptr>;

using std::filesystem::path;

inline path
cat(path left, const path &right)
{
  return left += right;
}

// Compare paths component by component so subtrees are contiguous
struct PathLess {
  static bool operator()(const path &a, const path &b)
  {
    return std::ranges::lexicographical_compare(a, b);
  }
};

using PathSet = std::multiset<path, PathLess>;

// Return a range for a subtree rooted at root.  root itself will be
// returned only if it does not contain a trailing slash.
inline auto
subtree(const PathSet &s, const path &root)
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
subtree_rev(const PathSet &s, const path &root)
{
  return subtree(s, root) | std::views::reverse;
}

std::string fdpath(int fd, bool must = false);

PathSet mountpoints(const path &mountinfo = "/proc/self/mountinfo");

// Calls fsconfig(FSCONFIG_CMD_CREATE) and fsmount.
Fd make_mount(int conffd, int attr = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV);

Fd clone_tree(int dfd, const path &file = {}, bool recursive = false);

void xmnt_move(int mountfd, const path &mountpath, int mountpointfd,
               const path &mountpointfile, int flags);

inline void
xmnt_move(int mfd, int mpfd, const path &mpfile = {}, int flags = 0)
{
  xmnt_move(mfd, path{}, mpfd, mpfile, flags);
}

void xmnt_setattr(int fd, const mount_attr &a,
                  unsigned int flags = AT_RECURSIVE);
void xmnt_propagate(int fd, std::uint64_t propagation, bool recursive = true);

template<std::convertible_to<const char *>... Opt>
requires (sizeof...(Opt) % 2 == 0)
Fd
make_tmpfs(Opt... opt)
{
  Fd conf = fsopen("tmpfs", FSOPEN_CLOEXEC);
  if (!conf)
    syserr(R"(fsopen("tmpfs"))");
  if constexpr (sizeof...(Opt)) {
    auto options = std::to_array<const char *>({opt...});
    for (auto i = 0uz; i < options.size() - 1; i += 2)
      if (fsconfig(*conf, FSCONFIG_SET_STRING, options[i], options[i + 1], 0))
        syserr(R"(fsconfig(tmpfs, "{}", "{}"))", options[i], options[i + 1]);
  }
  return make_mount(*conf);
}

void recursive_umount(const path &tree);

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
//    // now you no longer have the lock
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

inline struct stat
xfstat(int fd)
{
  struct stat sb;
  if (fstat(fd, &sb))
    syserr(R"(fstat("{}"))", fdpath(fd));
  return sb;
}

using ACL = RaiiHelper<acl_free, acl_t>;

enum AclType {
  kAclAccess = ACL_TYPE_ACCESS,   // Set ACL on inode
  kAclDefault = ACL_TYPE_DEFAULT, // Set ACL for files created in directory
};
void set_fd_acl(int fd, const char *acltext, AclType which = kAclAccess);
