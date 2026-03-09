
#include "cred.h"
#include "jai.h"

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

