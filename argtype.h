// -*-C++-*-

#pragma once

#include <concepts>
#include <tuple>
#include <type_traits>

namespace detail {
template<typename F> struct ArgTypeHelper;

template<typename F> requires (!std::same_as<F, std::decay_t<F>>)
struct ArgTypeHelper<F> : ArgTypeHelper<std::decay_t<F>> {};

template<typename R, typename... A, bool NE>
struct ArgTypeHelper<R (*)(A...) noexcept(NE)> {
  using type = std::tuple<A...>;
};

template<typename O> requires requires { &O::operator(); }
struct ArgTypeHelper<O> {
private:
  template<typename R, typename... A>
  static std::tuple<A...> return_arg_type(R (O::*)(A...) const);
  template<typename R, typename... A>
  static std::tuple<A...> return_arg_type(R (O::*)(A...));

public:
  using type = decltype(return_arg_type(&O::operator()));
};
} // namespace detail

// Number of arguments that a function or callable object takes
template<typename F>
constexpr std::size_t kArity =
    std::tuple_size_v<typename detail::ArgTypeHelper<F>::type>;

// Nth argument type of a function or callable object
template<std::size_t N, typename F>
using ArgNType =
    std::tuple_element_t<N, typename detail::ArgTypeHelper<F>::type>;

// Argument type of a function callable object with one argument
template<typename F> requires (kArity<F> == 1)
using UnaryType = ArgNType<0, F>;
