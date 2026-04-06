---
title: jai(1)
author: David Mazieres
outline: [1,2]
---

# NAME

jai - Jail an AI agent

# SYNOPSIS

`jai` `--init` \
`jai` [*option*]...  [*cmd* [*arg*]...] \
`jai` `-u` [`-j` *jail*]

# DESCRIPTION

jai is a super-lightweight sandbox for AI agents requiring almost no
configuration.  By default it provides casual security, so is not a
substitute for using a proper container to confine agents.  However,
it is a great alternative to using no protection at all when you are
thinking of giving an agent full control of your account and all its
files.  Compared to the latter, jai can reduce the blast radius should
things go wrong.

By default, if you run "`jai` *cmd* [*arg*]...", it will execute *cmd*
with the specified arguments in a lightweight jail that has full
access to the current working directory and everything below,
copy-on-write access to an overlay mount of your home directory,
private `/tmp` and `/var/tmp` directories, and the rest of the file
system read-only.  Note, however, that device nodes remain usable
subject to normal permission checks; a read-only `/dev` mount does not
prevent opening devices read-write.  Note also inherited file
descriptors for file outside the jail can still be used by jailed
commands.  If you don't specify *cmd*, jai will launch a jailed shell
by default.

Executing a command in this way is known as _casual mode_, because
*cmd* can read most sensitive files on the system.  In other words,
jai prevents *cmd* from clobbering all your files, but doesn't provide
much confidentiality.

If you run `jai -mstrict` *cmd* [*arg*]...", then *cmd* will be run
with an empty home directory, using the credentials of the
unprivileged user `jai` on your system, but with the current working
directory mapped to its place and fully exposed.  Though the rest of
the system outside your home directory is available read-only, because
*cmd* is running with user `jai`'s credentials rather than yours, it
will not be able to read sensitive files that require your user ID or
group IDs (assuming you don't add `jai` to any supplemental groups,
which would be a strange thing to do).

Strict mode does not let you grant access to NFS file systems.  If
your home directory is on NFS, you can instead use bare mode with `jai
-mbare`.  Bare mode hides your entire home directory like strict mode,
but it runs jailed software with your user credentials, and hence
allows jailed software to use your credentials to read any sensitive
files you have access to outside your home directory.

Note that all modes use a private PID namespace, so jailed software
cannot kill or ptrace processes outside of the jail.  Moreover, all
modes have a private `/run/user/$UID/` directory
(a.k.a. `$XDG_RUNTIME_DIR`), since many sensitive daemons have sockets
in that directory.  Jai will let you expose that directory or
subdirectories of with the `-d` option, discussed below.  E.g., `jai
-d $XDG_RUNTIME_DIR/emacs` makes `emacsclient` in the jail open an
unjailed editor--**but** it also allows jailed software to request
evaluation of arbitrary elisp outside of the jail, eliminating any
security boundary (though still potentially guarding against
accidental file erasure).

By default, jai will store private home directories under
`$HOME/.jai`.  However, it needs the ability to set extended
attributes on casual jails, which is not possible if your home
directory is on NFS.  You can use the option
`--storage=/some/local/directory` to store private home directories in
a different location, as long as you own the storage directory.
Alternatively, you can set the `JAI_CONFIG_DIR` environment variable
to move your entire configuration directory from `$HOME/.jai` to a
local disk.

If you want to grant access to directories other than the current
working directory, you can specify additional directories with the
`-d` option, as in `jai -d /local/build untrusted_program`.  If you
don't want to grant access to the current working directory, use the
`-D` option.  Note that by default, jai will refuse to run in your
home directory, on the assumption that this is probably a mistake and
that you don't want to grant your entire home directory to jailed
processes.  If you are in your home directory, you can launch jai with
`-D` to start in the sandboxed version of your home directory without
granting anything.  If you really want to grant your entire home
directory to the jail, you can still do so by running `jai -Dd $HOME`,
but since that negates most of jai's protections, it would only make
sense in unusual corner cases.

If you use casual mode and jailed software stores configuration files
in your home directory, you will find any such changes in
`$HOME/.jai/default.changes` (or wherever you specified for
`--storage`).  If you wanted these changes in your home directory, you
can destroy the jail with `jai -u`, move the changed files back into
your home directory, then re-run `jai` with the appropriate `-d` flag
to expose whatever directory contains the changed files (e.g.,
`$HOME/.application` or `$HOME/.config/application`).

jai allows the use of multiple home directories for different jails.
To use a home directory other than the default, just give it a name
with the `-j` option and it will be created on demand.  If you don't
specify `-mcasual` or `-mbare`, strict mode will become the default
for a newly created jail, but you can change this by editing the
corresponding `.jail` file in `$HOME/.jai` or wherever your storage
directory is.

# CONFIGURATION

Configuration comes from three sources: the command line, a `.conf`
configuration file (which may include other files via `conf` options),
and a `.jail` file specific to the named jail you are choosing.
Command-line options override everything, and `.jail` files override
`.conf` files (except that `.jail` files cannot select a different
jail).

If you don't specify a `.conf` file on the command line with the `-C`
option, and if *cmd* does not contain any slashes, jai will first try
to use `$HOME/.jai/`*cmd*`.conf` if that file exists, and otherwise
will use `$HOME/.jai/default.conf` (which it will create if
necessary).  That way the `.conf` file can specify a jail name and the
`.jail` file can set the mode of the jail.

The format of `.conf` and `.jail` configuration files is a series of
lines of the form "*option* [*value*]" or "*option*`=`*value*".
*option* can be any long command-line option without the leading `--`,
for example:

    conf .defaults
    mode casual
    dir /local/build
    mask Mail

If you want to set an option that requires an argument to the empty
string, use an `=` sign, as in `storage=` to reset the default storage
location.

Within a configuration file, `conf` acts like an include directive,
logically replacing the `conf` line with the contents of another
configuration file.  Relative paths in `conf` include directives are
relative to `$HOME/.jai/` (or `$JAI_CONFIG_DIR` if set).  jai creates
a file `.defaults` with a sensible set of defaults you should probably
include directly or indirectly as the first thing in any `.conf`
configuration file you write.  (By including it first, anything else
in your `.conf` file will override the defaults.)

jai executes jailed programs with bash.  The `command` directive
allows you to reconfigure the environment or add command-line options
to certain commands.  For instance, to use a python virtual
environment in a jail, you might create a file `python.conf` with the
following:

    conf .defaults
    mode strict
    dir venv
    jail python
    command source $HOME/venv/bin/activate; "$0" "$@"

If you run `jai python`, this configuration file will load a virtual
environment before running the command.  For more complicated setup
logic, you can use `setenv` to set the `BASH_ENV` environment variable
to an initialization script to be sourced in non-interactive session.

The `dir`, `xdir`, `mask`, `unmask`, `setenv`, and `storage` options,
and `conf` options in configuration files will perform environment
variable substitution for variable names contained within `${`...`}`.
Note the braces are required, unlike in the shell.  You can quote a
literal `$` or `\` by preceding it with a backslash `\`.

# EXAMPLES

To install claude code in a jail called `claude`:

    curl -fsSL https://claude.ai/install.sh | \
        jai -D -mstrict -j claude bash

(Note that jai runs your login shell by default, so if your shell is
`bash`, then you can just pipe `curl` to `jai -D -mstrict -j claude`
without even specifying bash.)  To invoke claude code in that same
jail, if `$HOME/.local/bin` is not already on your path:

    PATH=$HOME/.local/bin:$PATH jai -j claude claude

To make `jai claude` use the claude jail by default:

    cat <<'EOF' >$HOME/.jai/claude.conf
    conf .defaults
    jail claude
    setenv PATH=${HOME}/.local/bin:${PATH}
    EOF

Now you can run `jai claude` to invoke claude code with access to the
current working directory, and `jai -C claude` to get a shell with the
same permissions as claude, so as to understand what claude is seeing.
To prohibit claude from changing git state when run in the root of a
git repository, you can make `$PWD/.git` read-only when it exists:

    cat <<'EOF' >$HOME/.jai/claude.conf
    conf .defaults
    jail claude
    rdir? ${PWD}/.git
    setenv PATH=${HOME}/.local/bin:${PATH}
    EOF

To make `jai claudeyolo` run claude in dangerous mode, you
could create another configuration file like this:

    cat <<'EOF' > $HOME/.jai/claudeyolo.conf
    # Start with claude's defaults
    conf claude

    # Add a shell function that will expand "claudeyolo" to the
    # appropriate claude command for destroying your file system.
    # (Note semicolon before the right brace and after, and backslash
    # for continuation lines in the configuration file.)
    command claudeyolo(){ \
        claude --permission-mode bypassPermissions "$@"; \
      }; "$0" "$@"
    EOF

The author is not advocating doing the above!  But if you are going to
use claude in dangerous mode, better to make the alias available only
in jai, not in your unconfined shells, so you don't accidentally
invoke the mode without jai.

Suppose you want to make your X11 session available in the claude jail
to facilitate pasting images into claude.  This significantly reduces
security, so isn't necessarily a good idea, but you can do it by
extracting your authentication cookies in your current working
directory and merging them into your claude jail.

    # Extract cookies outside jail, merge them inside jail
    xauth extract - $DISPLAY | jai -C claude xauth merge -

    # Now copy a screen region to paste into claude...
    import png:- | xclip -selection clipboard -t image/png

A safer way to do this is to write your screengrabs directly into the
sandbox's `/tmp` directory as in:

    import /run/jai/$USER/tmp/claude/scrn.png

Then in claude, just incorporate the image with `@/tmp/scrn.png`.

To use an existing codex or opencode installation in casual mode (less
safe) and have it update configuration files in your real home
directory:

    jai -d ~/.codex codex

    jai -d ~/.config/opencode -d ~/.local/share/opencode opencode

To do this by default when invoking `jai codex` (similar for `jai
opencode`):

    cat <<EOF >$HOME/.jai/codex.conf
    conf .defaults

    # list additional directories to expose
    dir .codex
    EOF

Suppose that you put a skeletal set of dot files in
`$HOME/.jai/.skel`--for example, `$HOME/.jai/.skel/.bashrc`,
`$HOME/.jai/.skel/.inputrc` and you want all newly created strict or
bare jails to have these files in the home directory.  Suppose further
that you want to make sure github's public SSH keys are always in your
`known_hosts` files, even though you mask `.ssh` in casual jails.  You
could create an initialization script as follows:

``` bash
cat > ~/.jai/.initjail <<'EOF'
#!/bin/bash

# Out of paranoia, make sure this isn't run in your real
# home directory
if [[ $(readlink -f "$HOME") == $(readlink -f .) ]]; then
    echo Do not run this in your real home directory>&2
    exit 1
fi

# When creating strict/bare mode jails, populate the new home
# directory with the contents of $HOME/.jai/.skel/
if [[ $JAI_MODE == strict || $JAI_MODE == bare ]]; then
    cp -rL "$JAI_CONFIG_DIR/.skel/." .
fi

# In any kind of new jail, copy github's public key to your new .ssh
# directory.  (Casual jails mask .ssh by default, so you need to
# create the directory regardless of mode.)
mkdir --mode=0700 .ssh
grep -E "^github.com " "$HOME/.ssh/known_hosts" > .ssh/known_hosts
EOF

chmod +x ~/.jai/.initjail
echo initjail .initjail >> ~/.jai/.defaults
```

If you prevent jailed processes from inheriting any file descriptors
other than 0,1, and 2, you can use a script to close all file
descriptors other than these and file descriptor 255 (which bash
uses).  For example, you could add the following lines to
`$HOME/.jai/.jairc` and refresh your `.defaults` file (run `jai
--print-defaults`) if `command` does not already source `$JAI_SCRIPT`:

```bash
scrub_fds() {
  local p fd

  for p in /proc/$$/fd/*; do
    fd=${p##*/}

    case $fd in
      0|1|2|255) continue ;;
      ''|*[!0-9]*) continue ;;
    esac

    eval "exec $fd<&- $fd>&-" 2>/dev/null || :
  done
}

test -n "${JAI_KEEP_FDS+set}" || scrub_fds
```

Then unless you set the `JAI_KEEP_FDS` environment variable, file
descriptors will be scrubbed by default in sandboxes.


# OPTIONS

`--init`
: Create default configuration files and exit.  Gives you a chance to
  edit the default configuration files before creating any jails.

`-C` *file*, `--conf` *file*, `--conf?` *file*
: Specifies the configuration file to read.  If *file* does not
  contain a `/`, the file is relative to `$HOME/.jai`.  Also, if
  *file* resides in `$HOME/.jai` and does not contain a `/`, you can
  omit any `.conf` extension.  So `-C default` is equivalent to `-C
  default.conf` (assuming you don't have a file `default` in addition
  to `default.conf`).  Unlike the first two options, `--conf?` does
  not cause an error if file does not exist.

    If no configuration file is specified, the default is based on the
  *cmd* argument.  If *cmd* contains no slashes and does not start
  with `.`, the system will use `$HOME/.jai/`*cmd*`.conf` if such a
  file exists.  Otherwise it uses `$HOME/.jai/default.conf`.

    Note that command-line arguments are parsed both before and after
  the file specified by the `-C` or `--conf` option.  Hence,
  command-line options always take precedence over configuration files
  (though this works slightly differently for `--script`, described
  below).  When `conf` is specified in a configuration file, however,
  the behavior is different.  The specified file is read at the exact
  point of the `conf` directive, overriding previous lines and subject
  to being reversed by subsequent lines.

`-d` *dir*, `--dir` *dir*, `--dir!` *dir*
: Grant full access to directory *dir* and everything below in the
  jail.  You must own *dir*.  You can supply this option multiple
  times.  Note that on the command line, relative paths are relative
  to the current working directory, while in configuration files, they
  are relative to your home directory.  The `--dir!` form creates the
  directory if it didn't already exist.

`-r` *dir*, `--rdir` *dir*, `--rdir?` *dir*
: Like `--dir`, but grant _read-only_ access to directory *dir*.  Like
  `-d` and `--dir`, `-r` and `--rdir` cause an error if the directory
  does not exist, while `--rdir?` is silently ignored if the directory
  does not exist.

`-x` *dir*, `--xdir` *dir*
: Reverse the effects of a previous `--dir` *dir* or `--rdir` *dir*
  option.

`-D`, `--nocwd`
: By default, `jai` grants access to the current working directory
  even if it is not specified with `-d`.  This option suppresses that
  behavior.  If you run with `-D` and no `-d` options, your entire
  home directory will be copy-on-write (in casual mode) or empty (in
  bare or strict mode) and nothing will be directly exported.

`-m` {`casual`|`bare`|`strict`}, `--mode` {`casual`|`bare`|`strict`}
: Set jai's execution mode.  In casual mode, the user's home directory
  is made available as an overlay mount.  Casual mode protects against
  destruction of files outside of granted directories, but does not
  protect confidentiality:  jailed code can read most files accessible
  to the user.  You can hide specific files with the `--mask` option
  or by deleting them under `/run/jai/$USER/*.home`, but because
  casual mode makes everything readable by default, it cannot protect
  all sensitive files.

    In strict mode, the user's home directory is replaced by an empty
  directory (`$HOME/.jai/`*name*`.home`), and jailed code runs with a
  different user id, `jai`.  Id-mapped mounts are used to map `jai` to
  the invoking user in granted directories.  Strict mode is the
  default when you name a jail (see `--jail`), but not for the default
  jail.

    Bare mode uses an empty directory like strict mode, but runs with
  the invoking user's credentials.  It is inferior to strict mode, but
  can be used for NFS-mounted home directories since NFS does not
  support id-mapped mounts.

`-j` *name*, `--jail` *name*
: jai allows you to have multiple jailed home directories, which may
  be useful when jailing multiple tools that should not have access to
  each other's API keys.  This option specifies which jail to use.  If
  no such jail exists yet, it will be created on demand and the mode
  specified (strict by default) will become the default for that jail,
  though you can change it in the file `$HOME/.jai/`*name*`.jail`.

    Note that if you switch modes, the same *name* can have both a
  casual home directory (accessible at `/run/jai/$USER/`*name*`.home`,
  with changes going in `$HOME/.jai/`*name*`.changes`) and a
  strict/bare home directory (in `$HOME/.jai/`*name*`.home`).  There
  is no special relation between these two home directories, but all
  jails by the name *name* share the same `/tmp` directory.

    Note that you are not allowed to use the `jail` configuration option
  in a `.jail` file or any configuration file included by the `.jail`
  file.

`--mask` *file*
: When creating an overlay home directory, create a "whiteout" file to
  hide *file* in the jail.  *file* must be a relative path and is
  always relative to your home directory, regardless of where you run
  jai.  You can specify this option multiple times.  An easier way to
  hide files is just to delete them from `/run/jai/$USER/*.home`;
  hence, this option is mostly useful in configuration files to
  specify a set of files to delete by default.  If you add `mask`
  directives to your configuration file, you will need to clear mounts
  with `jai -u` before the changes take effect.

`--unmask` *file*
: Reverse the effects of a previous `--mask` option.  This does not
  unmask files that have already been masked in an existing jail.  For
  that, you need to go into `$HOME/.jai/`*name*`.changes` and manually
  remove the whiteout files.  It also does nothing if you have masked
  a parent directory of *file*.  The main utility of this option is to
  reverse `mask` lines in a configuration file.  For instance, you can
  include a default set of masked files with a `conf` option and then
  surgically remove individual masked files that you want to expose.

`--unsetenv` *var*
: Filters *var* from the environment of the jailed program.  Can be
  the name of an environment variable, or can use the wildcard `*` as
  in `*_PID`.  (Since jailed processes don't see outside processes,
  you might as well filter any PIDs exposed in environment variables
  to avoid confusion.)

`--setenv` *var*, `--setenv` *var*`=`*value*
: There are two forms of this command.  If the argument does not
  contain `=`, then `--setenv` reverses the effect of `--unsetenv`
  *var*.  If *var* is a pattern, it must exactly match the unset
  pattern you want to remove.  For example, `--unsetenv=*_PASSWORD
  --setenv=IPMI_PASSWORD` and `--unsetenv=IPMI_PASSWORD
  --setenv=IPMI_PASSWORD` will both pass the `IPMI_PASSWORD`
  environment variable through to the jail, while
  `--unsetenv=*_PASSWORD --setenv=IPMI_*` will not.

    If the argument contains `=`, then *var* is always treated as a
  variable, not a pattern, and it is assigned *value* in the jail.

`--storage` *dir*
: Specify an alternate location in which to store private home
  directories and overlays.  The default is `$JAI_CONFIG_DIR` if set,
  otherwise `$HOME/.jai`.  However, if your home directory is on NFS
  you may wish to use storage on a local file system, as NFS does not
  support the extended attributes required by overlay file systems.
  You can of course install a symbolic link for each individual home
  directory, but `--storage` allows you to relocate the base directory
  where all jails are located.

`--script` *bash-file*, `--script?` *bash-file*
: If you specify one or more bash script files, they will be
  concatenated into a temporary file that will also delete itself when
  sourced, and the `JAI_SCRIPT` environment variable will point to
  this file in a jail.  Because you can run commands from bash using
  the `--command` option, the `--script` option allows you to define
  shell functions that operate as command aliases.  `--script` aborts
  with an error if *bash-file* does not exist, while `--script?`
  silently ignores a non-existent or inaccessible file.  On the
  command-line, the path of *bash-file* is relative to the current
  working directory, while in a configuration file it is relative to
  `$JAI_CONFIG_DIR` (or `$HOME/.jai` if not set).

    The concatenated script file will also try to delete itself to
  keep your `/tmp` directory clean.  You can disable this behavior and
  keep the script around for the duration of the sandbox run by
  setting the `JAI_KEEP_SCRIPT` environment variable.  If you are
  getting some error message, you can run `JAI_KEEP_SCRIPT=1 jai
  -C`*conf* (with no command) to get a shell, and then examine the
  file `$JAI_SCRIPT` from within the sandbox.

    Note that each script file is included only once in the
  concatenated file, starting with script files specified on the
  command line, then those in `.conf` file, then those in `.jail`
  files.  This is because earlier files can bypass processing of later
  ones by using the bash `return` builtin, or can make variables
  read-only via the `readonly` or `declare -r` bash builtins.

`--initjail` *program*, `--initjail?` *program*
: If the jail does not exist yet, then after creating it, jai will run
  *program* outside any jail, but with the current working directory
  set to the external location of what the jails home will be.  In
  casual jails, the current working directory will be
  `/run/jai/$USER/`*jail*`.home`, while in bare and strict jails it
  will be `$JAI_CONFIG_DIR/`*jail*`.home`.  (`$JAI_CONFIG_DIR` will
  always be set in the script, even if you are using the default
  location of `$HOME/.jai`.)  You can use this to set an executable
  script to populate the home directories of newly created jails from
  your existing home directory.  Be sure to check the `$JAI_MODE`
  environment variable as you will probably want to initialize casual
  jails differently from strict/bare jails.

    Note that *program* is relative to the current working directory
  when `--initjail` is specified on the command line, and relative to
  `$JAI_CONFIG_DIR` when specified in a configuration file.

`--command` *bash-command*
: If you set this option, jai will launches the jailed program you
  specify by running "`/bin/bash -c` *bash-command* *cmd* *arg*...".
  You can run the program as `"$0" "$@"` in *bash-command*, but the
  option allows you to set an environment variable or source an rc
  script.  The `.defaults` file created by default uses `--command` to
  source all the scripts you have specified with `--script`.

`-u`
: Unmounts all overlay directories from `/run/jai` and cleans up
  overlay-related files in `$HOME/.jai/*.work` that the user might not
  be able to clean up without root.  This option also destroys the
  private `/tmp` and `/var/tmp` directories (same directory at both
  mount points), so make sure you don't need anything in there.

    Overlay mounts for casual jails are created under
  `/run/jai/$USER/*.home` and left around between invocations of jai.
  If you wish to change "upper" directories `$HOME/.jai/*.changes`,
  the changes may not take effect until the file system is unmounted
  and remounted.  For that reason, `--mask` options are only applied
  when first creating the overlay mount.  Hence, you must run `jai -u`
  before changing `--mask` options or directly editing the changes
  directory.

    If you specify `-j` *jail* in addition to `-u`, jai will clean up
  only one specific jail.  For a casual jail, this means unmounting
  the overlay mount and cleaning the work directory.  Strict jails all
  share one copy of the password file (in which user `jai`'s home
  directory has been changed to the invoking user's home directory).
  `-u` will attempt to unmount and delete the password file, but may
  not be able to if other strict jails are still in use.

`--print-defaults`
: Prints the default contents for `$HOME/.jai/.defaults`.

`--version`
: Prints the version number and copyright and exit.

`--complete`
: This option is only valid as the first option on the command line.
  It tells jai not to do anything, but it prints a list of completions
  to assist shells in doing command completion.  For example: `jai
  --complete -m "c"` prints `casual`.  If the commands line is
  complete, then it will output the special string `_command_offset
  `*N*, which indicates that argument *N* is the start of a new
  command that should be completed according to the rules for that
  command.

# ENVIRONMENT

The following environment variables affect jai's operation:

`SUDO_USER`, `USER`
: If jai is invoked with real UID 0 and either of these environment
  variables exists, it will be taken as the user whose home directory
  should be sandboxed.  This makes it convenient to run `jai` via
  `sudo` if you don't want to install it setuid root.  If both are
  set, `SUDO_USER` takes precedence.

`JAI_CONFIG_DIR`
: Location of jai configuration files and private home directories, by
  default `$HOME/.jai`.  If your home directory is on NFS, you may
  wish to put your private home directories elsewhere in order to use
  casual mode.

Jai sets the following environment variables inside jails:

`JAI_MODE`
: Set to the mode (strict, bare, or casual) inside a jail.

`JAI_JAIL`
: Set to the selected jail name (specified by `-j` or `--jail`) inside
  the jail.

`JAI_USER`
: Set to the name of the user who invoked jai.

`JAI_SCRIPT`
: Inside a sandbox, if set, contains the path of a file containing the
  concatenation of all the script files specified with `--script`
  options.

`JAI_KEEP_SCRIPT`
: Usually the script file deletes itself as soon as it has been
  sourced.  If it is reporting errors and you want to debug it, set
  the JAI_KEEP_SCRIPT environment variable and the script will persist
  for the duration of the sandbox.  jai will still try to delete it on
  exit, however.

`PWD`
: Set to the current working directory.  Usually your shell will
  already set this variable, but jai guarantees it is correct, so you
  can expand it in configuration files.

# FILES

In the following paths, the location `$HOME/.jai` can be changed by
setting the `JAI_CONFIG_DIR` environment variable.

`$HOME/.jai/default.conf`, `$HOME/.jai/`*cmd*`.conf`
: Configuration file if none is specified with `-C`.  If there is a
  file for *cmd*, then *cmd*`.conf` is used.  Otherwise `default.conf`
  is used.

`$HOME/.jai/.defaults`
: Reasonable system defaults to be included in `default.conf` or
  *cmd*`.conf`.  This file is created automatically by jai.  The file
  has no effect if you don't include it, but you should probably begin
  all configuration files with the line `conf .defaults` to get the
  defaults.

In the following paths, the location `$HOME/.jai` is changed by the
`--storage` option.  In the absence of a `--storage` option, the
location can be changed by the `JAI_CONFIG_DIR` environment variable.

`$HOME/.jai/`*name*`.jail`
: Configuration file for jail named *name*, read after and overriding
  any settings in the `.conf` file.  Usually only sets `mode` for the
  sandbox, but could also conceivably include `dir` and other options
  except `jail`, which is disallowed.

`$HOME/.jai/default.changes`, `$HOME/.jai/`*name*`.changes`
: This "upper" directory is overlaid on your home directory and
  contains changes that have been made inside a casual jail.  Before
  directly changing this directory, tear down and recreate the
  sandboxed home directory with `jai -u`.  The non-default version is
  used when you specify `-j` *name* on the command line.  If you
  specified `--storage=`*dir*, the changes directory will looked up
  under *dir* instead of `$HOME/.jai` (though in either case may be a
  symbolic link elsewhere).

`$HOME/.jai/default.work`, `$HOME/.jai/`*name*`.work`
: This "work" directory is required by overlayfs, but does not contain
  anything user-accessible.  Every once in a while the overlay file
  system may create files in here that you cannot delete.  If you are
  trying to delete an overlay directory to start from scratch and
  cannot delete this directory, try running `jai -u`, which will clean
  things up.  If you specified `--storage=`*dir*, or used a symbolic
  link for your changes directory, then the work directory will always
  be next to the changes directory wherever that lives.

`$HOME/.jai/default.home`, `$HOME/.jai/`*name*`.home`
: Private home directory for bare and strict jails.  If you specified
  `--storage=`*dir*, these directories will be under *dir* instead
  of `$HOME/.jai`.

The following paths are always fixed, regardless of environment
variables or command-line options:

`/run/jai/$USER/default.home`, `/run/jai/$USER/`*name*`.home`
: Home directories for casual jails.  You can delete files with
  sensitive data in these jail directories to hide them from jailed
  processes, or see the `--mask` option.

`/run/jai/$USER/tmp/default`, `/run/jai/$USER/tmp/`*name*
: Private `/tmp` and `/var/tmp` directory (they are the same) in
  jails.

`/run/jai/$USER/tmp/.run/default`, `/run/jai/$USER/tmp/.run/`*name*
: Outside a sandbox, these paths provide access to `/run/user/$UID`
  inside either the default sandbox or the one named *name*.

# BUGS

Overlayfs needs an empty directory `$HOME/.jai/work`, into which it
places two root-owned directories `index` and `work`.  Usually these
directories are empty when the file system is unmounted.  However,
occasionally they contain files, in which case it requires root
privileges to delete the directories.  You can run `jai -u` to clean
these up if you are unable to delete them.

Overlayfs can be flaky.  If a casual jail stops working, try
unmounting it with `jai -u`.  If the attributes on the
`default.changes` directory get out of sync, it may require making a
new `default.changes` directory to get around mounting errors.

If the jailed program terminates with a signal, jai exits with status
255 rather than emulating the signal death.

# SEE ALSO

<https://github.com/stanford-scs/jai> - jai home page
