// -*-C++-*-

/* Simple lambda based option parser.  Handles both command lines and
   configuration files.  Given an object `Options o`, you can register
   options in any of the following ways:

     o(OPTION, LAMBDA [, HELP-STRING [, VALUE-STRING]]
     o(OPTION1, OPTION2, LAMBDA [, HELP-STRING [, VALUE-STRING]]
     o({OPTION1, ..., OPTION_N}, LAMBDA [, HELP-STRING [, VALUE-STRING]]

   Each option can be a two character string literal starting with a
   dash (e.g., "-o") or a three or more character string literal
   starting with two dashes (e.g., "--add").  All options supplied in
   the same invocation will have the same effect, which can be useful
   for adding a short alias to a long option (e.g., "--debug" and "-d"
   can mean the same thing).  VALUE-STRING is the name of the option
   argument in the help string, and has no effect for options that do
   not take arguments.

   Whether or not an option takes an argument is determined by LAMBDA:

   * If LAMBDA takes no arguments, the option takes no arguments.

   * If LAMBDA takes an argument, the option takes an argument.
     Arguments are converted from a std::string_view to the argument
     type T by the function parseopt::option_convert<T>.  Currently
     there are two overloads for converting strings and decimal
     integers.  If you want to convert other types, you could
     conceivably overload the function option_convert before including
     this file, but you cannot currently use ADL since T is a template
     argument, not a function argument.

   * If LAMBDA has a default argument, the option takes an optional
     argument.

   You can parse command-line options with Options::parse_argv and a
   configuration file with Options::parse_file.  When parsing a file,
   only long options are supported, without the dashes.  For instance,
   a configuration file line of the form "output myfile" is equivalent
   to the option "--output=myfile".

   Options::help() returns a help string.  Invalid options throw the
   Options::Error exception.  Here is some example usage:

   // -----------------------------------------------------------

   bool enable_a = false;
   int debug_level = 0;
   std::string output;

   Options o;

   // Option that takes no arguments
   o("--enable-a", [&] { enable_a = true; }, "enable a mode");

   // Option that takes an argument
   o("-o", "--output", [&](std::string arg) { output = arg; },
     "specify FILE as the output file", "FILE");

   // Option that takes an optional argument
   o("-d", "--debug", [&](int lvl = 5) { debug_level = lvl; },
     "set debug level to LEVEL (default 5)", "LEVEL");

   std::span<char *> args;      // non-option arguments
   try {
     args = o.parse_argv(argc, argv);
   } catch (const Options::Error &e) {
     std::print(stderr, "{}\nusage: {} [OPTIONS] file1 [file2...]\n{}",
                e.what(), argv[0], o.help());
     exit(1);
   }

   // -----------------------------------------------------------

   On error, the above code will print an error message like this:

   $ ./myprog --help
   unknown option --help
   usage: ./myprog [OPTIONS] file1 [file2...]
     --enable-a    enable a mode
     -o FILE, --output=FILE
                   specify FILE as the output file
     -d[LEVEL], --debug[=LEVEL]
                   set debug level to LEVEL (default 5)
*/

#pragma once

#include "err.h"

#include <cassert>
#include <charconv>
#include <concepts>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <map>
#include <memory>
#include <print>
#include <span>
#include <utility>
#include <vector>

namespace parseopt {

using std::size_t;

struct OptionError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

template<std::constructible_from<std::string_view> T>
inline T
option_convert(std::string_view arg)
{
  return T(arg);
}

template<std::integral T>
T
option_convert(std::string_view arg)
{
  T val{};
  auto [ptr, ec] = std::from_chars(arg.begin(), arg.end(), val, 10);
  if (ptr != arg.end() || ptr == arg.begin())
    err<OptionError>(R"(invalid integer "{}")", arg);
  return val;
}

struct OptConverter {
  std::string_view arg;
  template<typename T> requires requires { option_convert<T>(""); }
  operator T() const
  {
    return option_convert<T>(arg);
  }
};

template<typename F> concept is_noarg_action = std::invocable<F>;
template<typename F>
concept is_arg_action = requires(F f) { f(OptConverter{}); };
template<typename F> concept is_action = is_noarg_action<F> || is_arg_action<F>;

struct Action {
  enum HasArg { kNoArg = 1, kArg = 2, kOptArg = 3 };

  virtual ~Action() {};
  virtual HasArg has_arg() const noexcept = 0;
  virtual void operator()() = 0;
  virtual void operator()(std::string_view) = 0;
};

template<is_action F> struct ActionImpl : Action {
  F f_;

  ActionImpl(F f) noexcept : f_(std::move(f)) {}
  HasArg has_arg() const noexcept override
  {
    return HasArg((is_noarg_action<F> ? kNoArg : 0) |
                  (is_arg_action<F> ? kArg : 0));
  }
  void operator()() override
  {
    if constexpr (is_noarg_action<F>)
      f_();
    else
      throw std::logic_error("option requires argument");
  }
  void operator()(std::string_view arg) override
  {
    if constexpr (is_arg_action<F>)
      f_(OptConverter{arg});
    else
      throw std::logic_error("option should not have argument");
  }
};
template<typename F> ActionImpl(F) -> ActionImpl<F>;

struct Option : std::string_view {
  template<size_t N> requires (N >= 3)
  consteval Option(const char (&str)[N]) : std::string_view(str, N - 1)
  {
    if (str[0] != '-' || (N == 3 && str[1] == '-'))
      throw R"(Option must be of form "-c" or "--string")";
    if (find('=') != npos)
      throw "Option name must not contain '='";
  }
};

struct Options {
  struct Completions {
    enum Disposition {
      kNoCompletions = -1,
      kRawCompletions = -2,
      kArgCompletions = -3,
    };

    // If kind >= 0, then argv[kind] is the first non-option argument,
    // meaning the first argument that is not a valid syntactic option
    // (at least 2 characters, first character '-', total length 2 if
    // and only if the second argument is not '-') or the argument to
    // such an option.  If there is a "--" argument, then kind is the
    // position after that.
    //
    // If kind is kNoCompletions, then something went wrong (an
    // invalid argument somewhere) and nothing can be completed.
    //
    // If kind is kRawCompletions, then we are in the middle of an
    // option, so vals contains the full names of completed arguments.
    // E.g., if completing "-", it would include all options (both
    // short and long).
    //
    // If kind is kArgCompletions, then we are completing the argument
    // to a fully determined option,and vals has 3 elements as
    // follows:
    //
    //    - opt() is the option being completed (e.g., "-d" or "--dir")
    //
    //    - arg() is the current argument stem.  E.g., if the argument
    //      being completed is "--dir=/usr/lo" or just "/usr/lo"
    //      following "--dir", then it would be "/usr/lo".
    //
    //    - prepend() is what to prepend to completions generated.  In
    //      the case that the value is a separate argv element (e.g.,
    //      completing {"--dir", "/usr/lo"}) prepend() will be empty.
    //      In the case that the option and argument are in one argv
    //      element such as "--dir=/usr/lo" or "-mcasu", then
    //      prepend() would be "--dir=" or "-m".
    int kind = kNoCompletions;

    std::vector<std::string> vals;

    Completions() noexcept = default;
    explicit Completions(int k) noexcept : kind(k) {}
    Completions(int k, std::vector<std::string> v) noexcept
      : kind(k), vals(std::move(v))
    {}

    std::string_view index_vals(size_t n) const
    {
      assert(kind == kArgCompletions && vals.size() == 3 && n < 3);
      return vals[n];
    }
    auto opt() const { return index_vals(0); }
    auto arg() const { return index_vals(1); }
    auto prepend() const { return index_vals(2); }
  };

  using enum Action::HasArg;
  using Error = OptionError;
  std::map<std::string, std::shared_ptr<Action>, std::less<>> actions_;
  std::string help_;

  Options &operator()(std::initializer_list<Option> options, is_action auto f,
                      std::string helpstr = {}, std::string valname = {})
  {
    auto action = std::make_shared<ActionImpl<decltype(f)>>(std::move(f));
    if (valname.empty())
      valname = "VAL";
    std::string optstr;
    for (const auto &opt : options) {
      assert(!actions_.contains(std::string(opt)) &&
             "duplicate option registration");
      actions_[std::string(opt)] = action;
      if (helpstr.empty())
        continue;
      if (!optstr.empty())
        optstr += ", ";
      optstr += opt;
      if (auto ha = action->has_arg(); ha != kNoArg) {
        if (ha == kOptArg)
          optstr += '[';
        else if (opt.size() == 2)
          optstr += ' ';
        if (opt.size() > 2)
          optstr += '=';
        optstr += valname;
        if (ha == kOptArg)
          optstr += ']';
      }
    }
    if (!helpstr.empty()) {
      constexpr size_t kIndent = 16;
      for (size_t i = 0; (i = helpstr.find('\n', i)) != helpstr.npos;
           i += kIndent)
        helpstr.insert(++i, std::string(kIndent, ' '));
      if (auto sz = optstr.size(); sz <= kIndent - 3)
        help_ += std::format("  {:<{}}{}\n", optstr, kIndent - 2, helpstr);
      else
        help_ += std::format("  {}\n{}{}\n", optstr, std::string(kIndent, ' '),
                             helpstr);
    }
    return *this;
  }

  Options &operator()(Option opt, is_action auto f, std::string helpstr = {},
                      std::string valname = {})
  {
    return (*this)({opt}, std::move(f), std::move(helpstr), std::move(valname));
  }
  Options &operator()(Option opt1, Option opt2, is_action auto f,
                      std::string helpstr = {}, std::string valname = {})
  {
    return (*this)({opt1, opt2}, std::move(f), std::move(helpstr),
                   std::move(valname));
  }

  void erase(std::string_view opt)
  {
#ifdef __cpp_lib_associative_heterogeneous_erasure
    actions_.erase(opt);
#else  // !__cpp_lib_associative_heterogeneous_erasure
    if (auto it = actions_.find(opt); it != actions_.end())
      actions_.erase(it);
#endif // !__cpp_lib_associative_heterogeneous_erasure
  }

  template<std::convertible_to<std::string_view> S>
  std::span<S> parse_argspan(std::span<S> args)
  {
    using enum ScanItem::Kind;

    auto res = scan_args(args);
    for (const auto &item : res.scan) {
      switch (item.kind) {
      case kOption:
        (*item.action)();
        break;
      case kOptionArg:
        (*item.action)(item.arg);
        break;
      case kNeedNextArg:
        err<Error>("option {} requires an argument", item.opt);
      case kUnknownOption:
        err<Error>("unknown option {}", item.opt);
      case kUnexpectedArg:
        err<Error>("option {} takes no argument", item.opt);
      case kPositionalHere:
      case kPositionalNext:
        std::unreachable();
      }
    }
    return args.subspan(res.positional);
  }

  // Returns all valid completions for argv[argc-1].  Or, if at some
  // point there is a non-option argument returns the position of the
  // first non-option argument in CompletionResult::kind.
  //
  // argc and argv are the complete argument vectors from main.
  //
  // optind is where to start parsing arguments.  For example, if your
  // program has a special mode "myprog --complete ..." to generate
  // completions, then optind would start at 2 in order to skip the
  // --complete argument that selects completion mode.
  //
  // Prefers a space after arguments with has_arg() == kArg, so will
  // append a space instead of '=' when completing such long
  // arguments, but also understands when there is an option such as
  // "--dir=/usr/lo" and will an arg of {"--dir", "/usr/lo", "--dir="}
  // (where arg[2] is what you need to prepend to completions of
  // "/usr/lo" in the output).
  Completions complete_args(int optind, int argc, char **argv);

  std::span<char *> parse_argv(int argc, char **argv)
  {
    return parse_argspan(std::span{argv + 1, argv + argc});
  }

  void parse_file(std::string_view text, std::string_view errpath = {});

  const std::string &help() const { return help_; }

private:
  struct ScanItem {
    enum Kind {
      kOption,         // Parsed a complete option with no attached argument.
      kOptionArg,      // Parsed an option with an attached argument.
      kNeedNextArg,    // Parsed an option that consumes the next argv element.
      kPositionalHere, // The current argv element is the first positional arg.
      kPositionalNext, // The next argv element is the first positional arg.
      kUnknownOption,  // Saw an option name that is not registered.
      kUnexpectedArg,  // Saw an argument attached to an option that takes none.
    };

    Kind kind = kUnknownOption;
    std::string opt;
    std::string_view arg;
    Action *action = nullptr;

    ScanItem(Kind k, std::string o = {}, std::string_view a = {},
             Action *act = nullptr) noexcept
      : kind(k), opt(std::move(o)), arg(a), action(act)
    {}
  };
  using Scan = std::vector<ScanItem>;

  struct ScanArgsResult {
    Scan scan;
    size_t positional; // index of first positions (non-options) argument
  };

  Action *get_action_ptr(std::string_view opt)
  {
    if (auto it = actions_.find(opt); it != actions_.end())
      return it->second.get();
    return nullptr;
  }

  Scan scan_arg(std::string_view optarg);

  template<std::convertible_to<std::string_view> S>
  ScanArgsResult scan_args(std::span<S> args)
  {
    using enum ScanItem::Kind;

    ScanArgsResult ret{.scan = {}, .positional = args.size()};
    for (size_t i = 0; i < args.size(); ++i) {
      auto items = scan_arg(args[i]);
      for (auto &item : items) {
        if (item.kind == kPositionalHere) {
          ret.positional = i;
          return ret;
        }
        if (item.kind == kPositionalNext) {
          ret.positional = i + 1;
          return ret;
        }
        if (item.kind == kNeedNextArg && i + 1 < args.size()) {
          item.kind = kOptionArg;
          item.arg = args[++i];
        }
        ret.scan.push_back(std::move(item));
        if (ret.scan.back().kind != kOption &&
            ret.scan.back().kind != kOptionArg)
          return ret;
      }
    }
    return ret;
  }
};

} // namespace parseopt

using parseopt::Options;
