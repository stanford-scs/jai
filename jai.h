// -*-C++-*-

#pragma once

#include "err.h"

#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

inline pid_t
xfork(std::uint64_t flags = 0)
{
  clone_args ca{.flags = flags, .exit_signal = SIGCHLD};
  if (auto ret = syscall(SYS_clone3, &ca, sizeof(ca)); ret != -1)
    return ret;
  syserr("clone3");
}

#define xsetns(fd, type)                                                       \
  do {                                                                         \
    if (setns(fd, type)) {                                                     \
      warn("setns({}, {}): {}", fdpath(fd), #type, strerror(errno));           \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

extern const std::string jai_defaults;
extern const std::string default_conf;
