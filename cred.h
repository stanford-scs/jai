// -*-C++-*-

#pragma once

#include "err.h"

#include <format>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

// Something that can contain a user or group id
using ugid_t = std::common_type_t<uid_t, gid_t>;

// Wrapper around getpw{nam,uid}_r and getgr{nam,gid}_id
template<typename Ent, auto IdFn, auto NamFn> struct DbEnt {
  Ent *p_{};
  Ent ent_;
  std::vector<char> buf_;

  DbEnt() noexcept = default;
  DbEnt(DbEnt &&other)
    : p_(std::exchange(other.p_, nullptr)), ent_(other.ent_),
      buf_(exchange(other.buf_, {}))
  {}
  DbEnt &operator=(DbEnt &&other) noexcept
  {
    p_ = std::exchange(other.p_, nullptr);
    ent_ = other.ent_;
    swap(buf_, other.buf_);
    return *this;
  }

  explicit operator bool() const { return p_; }
  const Ent *operator->() const { return p_; }
  Ent *get() const { return p_; }

  static DbEnt get_id(ugid_t n) { return get(IdFn, n); }
  static DbEnt get_nam(const char *n) { return get(NamFn, n); }

  static DbEnt get(auto fn, auto key)
  {
    DbEnt ret;
    ret.buf_.resize(std::max(128uz, ret.buf_.capacity()));
    for (;;) {
      int r = fn(key, &ret.ent_, ret.buf_.data(), ret.buf_.size(), &ret.p_);
      if (!r)
        return ret ? std::move(ret) : DbEnt{};
      else if (r == ERANGE)
        ret.buf_.resize(2 * ret.buf_.size());
      else
        errno = r, syserr("DbEnt<{}>::get", typeid(Ent).name());
    }
  }
};
using PwEnt = DbEnt<passwd, getpwuid_r, getpwnam_r>;
using GrEnt = DbEnt<group, getgrgid_r, getgrnam_r>;

struct Credentials {
  uid_t uid_ = -1;
  gid_t gid_ = -1;
  std::vector<gid_t> groups_;

  void make_effective() const;
  void make_real() const;
  std::string show() const;
  explicit operator bool() const noexcept { return uid_ != -1; }

  static Credentials get_user(const struct passwd *pw);
  static Credentials get_user(const PwEnt &e) { return get_user(e.get()); }
  static Credentials get_effective()
  {
    return Credentials{
        .uid_ = geteuid(),
        .gid_ = getegid(),
        .groups_ = getgroups(),
    };
  }
  static Credentials get_real()
  {
    return Credentials{
        .uid_ = getuid(),
        .gid_ = getgid(),
        .groups_ = getgroups(),
    };
  }

  static std::vector<gid_t> getgroups();

  friend bool operator==(const Credentials &,
                         const Credentials &) noexcept = default;
};

template<>
struct std::formatter<Credentials> : std::formatter<std::string_view> {
  using super = std::formatter<std::string_view>;
  auto format(const Credentials &creds, auto &ctx) const
  {
    return super::format(creds.show(), ctx);
  }
};

std::string make_id_map(ugid_t user, ugid_t untrusted);
