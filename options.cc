
#include "options.h"

void
Options::parse_file(std::string_view text, std::string_view errpath)
{
  static constexpr std::string_view ws = " \t\r";
  static constexpr std::string_view wsnl = " \t\r\n";
  static constexpr std::string_view wsnleq = " \t\r\n=";
  const size_t sz = text.size();
  auto clamp = [sz](size_t n) { return std::min(n, sz); };
  for (size_t pos = 0; pos < sz;) {
    try {
      if ((pos = text.find_first_not_of(wsnl, pos)) >= sz)
        break;
      if (text[pos] == '#') {
        pos = text.find('\n', pos);
        continue;
      }
      auto optend = clamp(text.find_first_of(wsnleq, pos));
      std::string optarg = "--";
      optarg += text.substr(pos, optend - pos);
      if ((pos = text.find_first_not_of(ws, optend)) >= sz ||
          text[pos] == '\n') {
        parse_argspan(std::span{&optarg, 1});
        continue;
      }
      if (text[pos] != '=')
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
    } catch (const Error &e) {
      if (errpath.empty())
        throw;
      auto nnl = std::count(text.begin(), text.begin() + clamp(pos), '\n');
      err<Error>("{}:{}: {}", errpath, nnl + 1, e.what());
    }
  }
}

Options::Scan
Options::scan_arg(std::string_view optarg)
{
  using enum ScanItem::Kind;
  if (optarg == "--")
    return {ScanItem{kPositionalNext}};
  if (optarg.size() < 2 || optarg.front() != '-')
    return {ScanItem{kPositionalHere}};

  if (optarg[1] == '-') {
    auto n = optarg.find('=');
    auto opt = optarg.substr(0, n);
    auto *action = get_action_ptr(opt);
    if (!action)
      return {ScanItem{kUnknownOption, std::string(opt)}};
    if (n == optarg.npos) {
      if (action->has_arg() == kArg)
        return {ScanItem{kNeedNextArg, std::string(opt), std::string_view{},
                         action}};
      return {ScanItem{kOption, std::string(opt), std::string_view{}, action}};
    }
    if (action->has_arg() == kNoArg)
      return {ScanItem{kUnexpectedArg, std::string(opt)}};
    return {
        ScanItem{kOptionArg, std::string(opt), optarg.substr(n + 1), action}};
  }

  Scan ret;
  for (size_t j = 1; j < optarg.size(); ++j) {
    std::string opt{'-', optarg[j]};
    auto *action = get_action_ptr(opt);
    if (!action) {
      ret.emplace_back(kUnknownOption, std::move(opt));
      return ret;
    }
    auto ha = action->has_arg();
    if (ha == kNoArg) {
      ret.emplace_back(kOption, std::move(opt), std::string_view{}, action);
      continue;
    }
    if (j + 1 < optarg.size())
      ret.emplace_back(kOptionArg, std::move(opt), optarg.substr(j + 1),
                       action);
    else if (ha == kOptArg)
      ret.emplace_back(kOption, std::move(opt), std::string_view{}, action);
    else
      ret.emplace_back(kNeedNextArg, std::move(opt), std::string_view{},
                       action);
    break;
  }
  return ret;
}

Options::Completions
Options::complete_args(int optind, int argc, char **argv)
{
  using enum ScanItem::Kind;

  auto opt = [&](std::string_view prefix) {
    Completions ret{Completions::kRawCompletions};
    for (auto it = actions_.lower_bound(prefix), e = actions_.end();
         it != e && it->first.starts_with(prefix); ++it) {
      std::string_view suffix;
      if (it->second->has_arg() != kOptArg)
        suffix = " ";
      else if (it->first.size() > 2)
        suffix = "=";
      ret.vals.push_back(std::format("{}{}", it->first, suffix));
    }
    return ret;
  };

  auto arg = [](std::string_view opt, std::string_view prefix,
                std::string_view prepend = {}) {
    return Completions{
        Completions::kArgCompletions,
        {std::string(opt), std::string(prefix), std::string(prepend)}};
  };


  if (optind >= argc)
    return Completions{argc};

  auto prefix = std::span{argv + optind, argv + argc - 1};
  auto scanned = scan_args(prefix);
  if (scanned.positional != prefix.size())
    return Completions{optind + int(scanned.positional)};

  if (!scanned.scan.empty()) {
    const auto &last = scanned.scan.back();
    switch (last.kind) {
    case kNeedNextArg:
      return arg(last.opt, argv[argc - 1]);
    case kOption:
    case kOptionArg:
      break;
    default:
      return {};
    }
  }

  std::string_view optarg(argv[argc - 1]);
  if (optarg == "-" || optarg == "--")
    return opt(optarg);
  if (optarg.size() < 2 || optarg.front() != '-')
    return Completions{argc - 1};

  if (optarg[1] == '-') {
    if (auto n = optarg.find('='); n != optarg.npos) {
      auto opt = optarg.substr(0, n);
      auto *action = get_action_ptr(opt);
      if (!action || action->has_arg() == kNoArg)
        return {};
      return arg(opt, optarg.substr(n + 1), optarg.substr(0, n + 1));
    }
    return opt(optarg);
  }

  for (size_t j = 1; j < optarg.size(); ++j) {
    auto opt = std::string({'-', optarg[j]});
    auto *action = get_action_ptr(opt);
    if (!action)
      return {};
    if (auto ha = action->has_arg();
        ha == kOptArg || (ha == kArg && j + 1 < optarg.size()))
      return arg(opt, optarg.substr(j + 1), optarg.substr(0, j + 1));
  }

  Completions ret{Completions::kRawCompletions};
  ret.vals.push_back(std::format("{} ", optarg));
  return ret;
}
