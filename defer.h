// -*-C++-*-

#pragma once

#include "argtype.h"

#include <concepts>
#include <functional>
#include <utility>

template<typename T, typename... Ts>
concept is_one_of = (std::same_as<T, Ts> || ...);

// Note that Destroy generally should not throw, whether or not it is
// declared noexcept.  Only an explicit call to reset() will allow
// exceptions to propagate.
//
// auto(Destroy) avoids warnings about ignored attributes on closedir.
template<auto Destroy, typename T = UnaryType<decltype(auto(Destroy))>,
         auto Empty = T{}>
struct RaiiHelper {
  T t_ = Empty;

  constexpr RaiiHelper() noexcept = default;
  RaiiHelper(T t) noexcept : t_(std::move(t)) {}
  RaiiHelper(RaiiHelper &&other) noexcept : t_(other.release()) {}
  ~RaiiHelper() { reset(); }

  template<typename Arg>
  requires is_one_of<std::decay_t<Arg>, T, decltype(Empty)>
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
  auto operator&() noexcept
  {
    return std::addressof(t_);
  }
  // Make it easier to use RaiiHelper with pointers in C libraries
  template<std::same_as<T> U = T> requires std::is_pointer_v<U>
  operator U() const
  {
    return t_;
  }
  decltype(auto) operator->(this auto &&self) noexcept { return (self.t_); }

  T release() noexcept { return std::exchange(t_, Empty); }

  template<typename Arg>
  requires is_one_of<std::decay_t<Arg>, T, decltype(Empty)>
  void reset(Arg &&arg) noexcept(noexcept(Destroy(std::move(t_))))
  {
    if (auto destroy_me = std::exchange(t_, std::forward<Arg>(arg));
        destroy_me != Empty)
      Destroy(std::move(destroy_me));
  }
  void reset() noexcept(noexcept(reset(Empty))) { reset(Empty); }
};

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
