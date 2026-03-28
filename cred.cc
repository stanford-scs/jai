
#include "cred.h"

#include <limits>

#include <grp.h>

void
Credentials::make_effective() const
{
  if (geteuid() != 0)
    seteuid(0);
  if (groups_ != getgroups() && setgroups(groups_.size(), groups_.data()))
    syserr("setgroups");
  if (gid_ != getegid() && setegid(gid_))
    syserr("setegid");
  if (seteuid(uid_))
    syserr("seteuid");
}

void
Credentials::make_real() const
{
  if (geteuid() != 0)
    seteuid(0);
  if (groups_ != getgroups() && setgroups(groups_.size(), groups_.data()))
    syserr("setgroups");
  if (gid_ != getgid() && setgid(gid_))
    syserr("setgid");
  if (setuid(uid_))
    syserr("setuid");
}

std::string
Credentials::show() const
{
  auto ret = std::format("uid={} gid={}", uid_, gid_);
  if (!groups_.empty()) {
    ret += " groups=";
    bool first = true;
    for (gid_t g : groups_) {
      if (first)
        first = false;
      else
        ret += ',';
      ret += std::to_string(g);
    }
  }
  return ret;
}

Credentials
Credentials::get_user(const struct passwd *pw)
{
  Credentials ret{.uid_ = pw->pw_uid, .gid_ = pw->pw_gid};
  int n = 0;
  if (getgrouplist(pw->pw_name, pw->pw_gid, nullptr, &n) != -1)
    return ret;
  ret.groups_.resize(n);
  if (getgrouplist(pw->pw_name, pw->pw_gid, ret.groups_.data(), &n) < 0)
    err("getgrouplist({}) failed", pw->pw_name);
  else if (size_t(n) != ret.groups_.size())
    err("getgrouplist({}) expected {} got {} groups", pw->pw_name,
        ret.groups_.size(), n);
  return ret;
}

std::vector<gid_t>
Credentials::getgroups()
{
  // Retry loop handles the unlikely race where supplementary groups
  // change between the sizing call and the filling call.
  for (int tries = 0; tries < 3; ++tries) {
    int n = ::getgroups(0, nullptr);
    if (n < 0)
      syserr("getgroups");
    auto ret = std::vector<gid_t>(size_t(n));
    n = ::getgroups(ret.size(), ret.data());
    if (size_t(n) == ret.size())
      return ret;
    if (n < 0)
      syserr("getgroups");
  }
  err("getgroups: group count keeps changing");
}

// Make a uid map mapping user to untrusted, leaving untrusted
// unmapped, and leaving everything else identical.
std::string
make_id_map(ugid_t user, ugid_t untrusted)
{
  auto max_mapped = std::numeric_limits<ugid_t>::max() - 1;

  std::string ret;
  auto add = [&ret](id_t inside, id_t outside, id_t count) {
    if (count != 0)
      ret += std::format("{} {} {}\n", inside, outside, count);
  };

  if (user == untrusted)
    add(0, 0, max_mapped + 1);
  else if (user < untrusted) {
    add(0, 0, user);
    add(user, untrusted, 1);
    add(user + 1, user + 1, untrusted - user - 1);
    // untrusted intentionally left unmapped
    add(untrusted + 1, untrusted + 1, max_mapped - untrusted);
  }
  else {
    add(0, 0, untrusted);
    // untrusted is intentionally left unmapped
    add(untrusted + 1, untrusted + 1, user - untrusted - 1);
    add(user, untrusted, 1);
    add(user + 1, user + 1, max_mapped - user);
  }

  return ret;
}
