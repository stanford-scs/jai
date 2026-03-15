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
     --enable-a  enable a mode
     -o FILE, --output=FILE
           specify FILE as the output file
     -d[LEVEL], --debug[=LEVEL]
           set debug level to LEVEL (default 5)
*/

#pragma once

#include "err.h"

#include <charconv>
#include <concepts>
#include <cstring>
#include <format>
#include <initializer_list>
#include <map>
#include <span>
#include <utility>

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

class Options {
public:
  using enum Action::HasArg;
  using Error = OptionError;

  Options &operator()(std::initializer_list<Option> options, is_action auto f,
                      std::string helpstr = {}, std::string valname = {})
  {
    auto action = std::make_shared<ActionImpl<decltype(f)>>(std::move(f));
    if (valname.empty())
      valname = "VAL";
    std::string optstr;
    for (const auto &opt : options) {
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
      if (auto sz = optstr.size(); sz < kIndent - 3)
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

  template<std::convertible_to<std::string_view> S>
  std::span<S> parse_argspan(std::span<S> args)
  {
    for (size_t i = 0; i < args.size(); ++i) {
      auto optarg = std::string_view(args[i]);
      if (optarg == "--")
        return args.subspan(i + 1);
      if (optarg.size() < 2 || optarg.front() != '-')
        return args.subspan(i);
      if (optarg[1] == '-') {
        std::string_view opt, arg;
        if (auto n = optarg.find('='); n == optarg.npos)
          opt = optarg;
        else {
          opt = optarg.substr(0, n);
          arg = optarg.substr(n);
        }
        auto &act = getopt(opt);
        auto ha = act.has_arg();
        if (!arg.empty()) {
          if (ha == kNoArg)
            err<OptionError>("option {} takes no argument", opt);
          act(arg.substr(1));
        }
        else if (ha != kArg)
          act();
        else if (i + 1 == args.size())
          err<OptionError>("option {} requires an argument", opt);
        else
          act(args[++i]);
      }
      else
        for (size_t j = 1; j < optarg.size(); j++) {
          auto &act = getopt(std::string({'-', optarg[j]}));
          auto ha = act.has_arg();
          if (ha == kNoArg) {
            act();
            continue;
          }
          if (j + 1 < optarg.size())
            act(optarg.substr(j + 1));
          else if (ha == kOptArg)
            act();
          else if (i + 1 == args.size())
            err<OptionError>("option -{} requires an argument", optarg[j]);
          else
            act(args[++i]);
          break;
        }
    }
    return {};
  }

  std::span<char *> parse_argv(int argc, char **argv)
  {
    return parse_argspan(std::span{argv + 1, argv + argc});
  }

  void parse_file(std::string_view text)
  {
    static constexpr std::string_view ws = " \t\r";
    static constexpr std::string_view wsnl = " \t\r\n";
    const size_t sz = text.size();
    auto clamp = [sz](size_t n) { return std::min(n, sz); };
    for (size_t pos = 0; pos < sz;) {
      if ((pos = text.find_first_not_of(wsnl, pos)) >= sz)
        break;
      if (text[pos] == '#') {
        pos = text.find('\n', pos);
        continue;
      }
      auto optend = clamp(text.find_first_of(wsnl, pos));
      std::string optarg = "--";
      optarg += text.substr(pos, optend - pos);
      if ((pos = text.find_first_not_of(ws, optend)) >= sz ||
          text[pos] == '\n') {
        parse_argspan(std::span{&optarg, 1});
        continue;
      }
      optarg += '=';

      bool escape = false, last_escaped = false;
      for (; pos < sz && (escape || text[pos] != '\n'); ++pos) {
        if (text[pos] == '\r')
          continue;
        if (!escape) {
          last_escaped = false;
          if (text[pos] == '\\')
            escape = true;
          else
            optarg += text[pos];
          continue;
        }
        escape = false;
        last_escaped = true;
        switch (text[pos]) {
        case 't':
          optarg += '\t';
          break;
        case 'r':
          optarg += '\r';
          break;
        case 'n':
          optarg += '\n';
          break;
        case '\n':
          pos = clamp(text.find_first_not_of(ws, pos + 1) - 1);
          break;
        default:
          optarg += text[pos];
          break;
        }
      }
      if (!last_escaped)
        while (wsnl.contains(optarg.back()))
          optarg.resize(optarg.size() - 1);
      parse_argspan(std::span{&optarg, 1});
    }
  }

  const std::string &help() const { return help_; }

private:
  std::map<std::string, std::shared_ptr<Action>, std::less<>> actions_;
  std::string help_;

  Action &getopt(std::string_view opt)
  {
    if (auto it = actions_.find(opt); it != actions_.end())
      return *it->second;
    err<OptionError>("unknown option {}", opt);
  }
};

} // namespace parseopt

using parseopt::Options;
