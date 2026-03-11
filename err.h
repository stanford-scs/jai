// -*-C++-*-

#pragma once

#include <filesystem>
#include <format>
#include <stdexcept>
#include <string>
#include <system_error>

#include <unistd.h>

extern std::filesystem::path prog;

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

template<typename... Args>
inline void
warn(std::format_string<Args...> fmt, Args &&...args)
{
  std::string msg = prog.filename();
  msg += ": ";
  msg += std::vformat(fmt.get(), std::make_format_args(args...));
  msg += '\n';
  write(2, msg.c_str(), msg.size());
}
