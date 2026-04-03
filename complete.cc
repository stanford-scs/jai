#include "jai.h"

#include <cassert>
#include <dirent.h>
#include <print>

using Completions = Options::Completions;

struct CompSet {
  const Completions &comp_;
  std::set<std::string> out_;

  CompSet(const Completions &comp) noexcept : comp_(comp) {}

  auto opt() const { return comp_.arg(); }
  auto arg() const { return comp_.arg(); }

  // Format one completion to be output
  template<typename... Args>
  void output(std::format_string<Args...> fmt, Args &&...args)
  {
    out_.insert(
        std::format("{}{}", comp_.prepend(),
                    std::vformat(fmt.get(), std::make_format_args(args...))));
  }
};

static void
complete_path(int dfd, CompSet &c, bool dir_only)
{
  path arg(c.arg());
  std::string stem = arg.filename();

  auto d = try_opendir(dfd, arg.parent_path(), kFollow);
  if (!d)
    return;
  while (auto de = readdir(*d)) {
    std::string_view name = d_name(de);
    if (name == "." || name == ".." || !name.starts_with(stem))
      continue;
    if (de->d_type == DT_UNKNOWN || de->d_type == DT_LNK) {
      struct stat sb;
      if (!fstatat(dirfd(*d), d_name(de), &sb, 0) && S_ISDIR(sb.st_mode))
        de->d_type = DT_DIR;
    }
    if (dir_only && de->d_type != DT_DIR)
      continue;
    c.output("{}{}", (arg.parent_path() / d_name(de)).string(),
             de->d_type == DT_DIR ? "/" : " ");
  }
}

static void
complete_config(int cfd, CompSet &c, std::string ext)
{
  auto d = try_opendir(cfd);
  if (!d)
    return;
  while (auto de = readdir(*d)) {
    path f = d_name(de);
    if (f.extension() != ext)
      continue;
    std::string name = f.replace_extension();
    if (!name.starts_with(c.arg()))
      continue;
    c.output("{} ", name);
  }
}

static void
complete_env(CompSet &c, bool eq)
{
  std::string_view arg = c.arg();
  for (char **e = environ; *e; ++e) {
    std::string_view var = *e;
    if (auto pos = var.find('='); pos == var.npos)
      continue;
    else
      var = var.substr(0, pos);
    if (var.starts_with(arg))
      c.output("{}{}", var, eq ? "=" : " ");
  }
}

int
Config::complete(Completions c)
{
  using enum Completions::Disposition;
  if (c.kind >= 0) {
    std::println("_command_offset {}", c.kind - 1);
    return 0;
  }
  if (c.kind == kNoCompletions)
    return 1;
  else if (c.kind == kRawCompletions) {
    for (const auto &v : c.vals)
      std::println("{}", v);
    return 0;
  }
  assert(c.kind == kArgCompletions);

  std::string_view opt = c.vals[0], arg = c.vals[1], prefix = c.vals[2];
  CompSet cs(c);

  if (std::ranges::contains(std::array{"-m", "--mode"}, opt)) {
    auto arg = c.arg();
    for (std::string_view sv : {"casual", "strict", "bare"}) {
      if (sv.starts_with(arg))
        cs.output("{} ", sv);
    }
  }
  else if (std::ranges::contains(std::array{"-d", "--dir", "--dir!", "-x",
                                            "--xdir", "-r", "--rdir", "--rdir?",
                                            "--storage"},
                                 opt))
    complete_path(AT_FDCWD, cs, true);
  else if (std::ranges::contains(std::array{"--script", "--script?"}, opt))
    complete_path(AT_FDCWD, cs, false);
  else if (std::ranges::contains(std::array{"--mask", "--unmask"}, opt))
    complete_path(home(), cs, false);
  else if (std::ranges::contains(std::array{"-C", "--conf", "--conf?"}, opt))
    complete_config(home_jai(), cs, ".conf");
  else if (std::ranges::contains(std::array{"-j", "--jail"}, opt))
    complete_config(storage(), cs, ".jail");
  else if (opt == "--setenv")
    complete_env(cs, true);
  else if (opt == "--unsetenv")
    complete_env(cs, false);

  for (const auto comp : cs.out_)
    std::println("{}", comp);

  return 0;
}
