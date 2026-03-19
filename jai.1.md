% jai(1)
% David Mazieres
%

# NAME

jai - Jail an AI agent

# SYNOPSIS

`jai` [*option*]...  [*cmd* [*arg*]...] \
`jai` `-u`

# DESCRIPTION

`jai` is a super lightweight sandbox for AI agents requiring almost no
configuration.  By default it provides casual security, so is not a
substitute for using a proper container to confine agents.  However,
it is a great alternative to using no protection at all when you are
thinking of giving an agent full control of your account and all its
files.  Compared to the latter, `jai` can reduce the blast radius
should things go wrong.

By default, if you run "`jai` *cmd* [*arg*]...", it will execute *cmd*
with the specified arguments in a lightweight jail that has full
access to the current working directory and everything below,
copy-on-write access to an overlay mount of your home directory,
private `/tmp` and `/var/tmp` directories, and read-only access to
everything else.  This is known as _casual mode_, because *cmd* can
read most sensitive files on the system.  In other words, jai prevents
*cmd* from clobbering all your files, but doesn't provide much
confidentiality.

If you don't specify *cmd*, jai will launch a jailed shell by default.

If you run `jai -mstrict` *cmd* [*arg*]...", then *cmd* will be run
with an empty home directory as an unprivileged user id, but with the
current working directory mapped to its place and fully exposed.
While the rest of the system outside the user's home directory is
available read-only, because *cmd* is running with a different user
ID, it will not be able to read sensitive files accessible to the
user.

If your home directory is on NFS, set the `JAI_CONFIG_DIR` environment
variable to a directory that you own on a local file system supporting
extended attributes.  Otherwise, overlay mounts may not work and you
may only be able to use bare mode (see below).

If you want to grant access to directories other than the current
working directory, you can specify addition directories with the `-d`
option, as in `jai -d /local/build untrusted_program`.  If you don't
want to grant access to the current working directory, use the `-D`
option.

If you use casual mode and forget to export some directory that you
updated in the jail, you will find changed files in
`$HOME/.jai/default.changes`.  You can destroy the sandbox with `jai
-u`, move the changed files back into your home directory, and re-run
`jai` with the appropriate `-d` flag.

jai allows the use of multiple sandboxed home directories.  To use a
home directory other than the default, just give it a name with the
`-n` option and it will be created on demand.  When you specify a home
directory with `-n`, strict mode becomes the default (unless there is
no unprivileged `jai` user on your system, in which case jai falls
back to bare mode).  It is possible to have multiple home overlays by
specifying `-mcasual` with `-n`.

# CONFIGURATION

If *cmd* does not contain any slashes, configuration is taken from
`$HOME/.jai/`*cmd*`.conf`, or, if no such file exists, from
`$HOME/.jai/default.conf`.  The format of the configuration file is a
series of lines of the form "*option* [*value*]".  *option* can be any
long command-line option without the leading `--`, for example:

    conf default.conf
    mode casual
    dir /local/build
    mask Mail

Within a configuration file, `conf` acts like an include directive,
logically replacing the `conf` line with the contents of another
configuration file.  (Relative paths are relative to `$HOME/.jai/`.)

jai executes programs with bash.  The `command` directive allows you
to reconfigure the environment or add command-line options to certain
commands.  For instance, to use a python virtual environment in a
jail, you might create a file `python.conf` with the following:

    conf default.conf
    mode strict
    dir venv
    name python
    command source $HOME/venv/bin/activate; "$0" "$@"

If you run `jai python`, this configuration file will load a virtual
environment before running the command.

# EXAMPLES

    jai -d ~/.claude claude

    jai -d ~/.codex codex

    mkdir -p ~/.local/share/opencode
    jai -d ~/.config/opencode -d ~/.local/share/opencode opencode

# OPTIONS

`-C` *file*, `--conf `*file*
: Specifies the configuration file to read.  If *file* does not
  contain a `/`, the file is relative to `$HOME/.jai`.

  If no configuration file is specified, the default is based on the
  *cmd* argument.  If *cmd* contains no slashes and does not start
  with `.`, the system will use `$HOME/.jai/`*cmd*`.conf` if such a
  file exists.  Otherwise it uses `$HOME/.jai/default.conf`.

  Note that command-line arguments are parsed both before and after
  the file specified by the `-C` or `--conf` option.  Hence,
  command-line options always take precedence over configuration
  files.  When `conf` is specified in a configuration file, however,
  the behavior is different.  The specified file is read at the exact
  point of the `conf` directive, so overriding previous lines and
  getting overridden by subsequent lines.

`-d` *dir*, `--dir` *dir*
: Grant full access to directory *dir* and everything below in the
  jail.  You must own *dir*.  You can supply this option multiple
  times.  Note that on the command line, relative paths are relative
  to the current working directory, while in configuration files, they
  are relative to your home directory.

`-D`, `--nocwd`
: By default, `jai` grants access to the current working directory
  even if it is not specified with `-d`.  This option suppresses that
  behavior.  If you run with `-D` and no `-d` options, your entire
  home directory will be copy-on-write (in casual mode) or empty (in
  bare or strict mode) and nothing will be directly exported.

`-m casual`|`bare`|`strict`, `--mode casual`|`bare`|`strict`
: Set jai's execution mode.  In casual mode, the user's home directory
  is made available as an overlay mount.  Casual mode protects against
  destruction of files outside of granted directories, but does not
  protect confidentiality:  sandboxed code can read most files
  accessible to the user.  You can hide specific files with the
  `--mask` option or by deleting them under `/run/jai/$USER/*.home`,
  but because casual mode makes everything readable by default, it
  cannot protect all sensitive files.

    In strict mode, the user's home directory is replaced by an empty
  directory (`$HOME/.jai/`*name*`.home`), and sandboxed code runs with
  a different user id, `jai`.  Id-mapped mounts are used to map `jai`
  to the invoking user in granted directories.  Strict mode is the
  default when you name a sandbox (see `--name`), but not for the
  default sandbox.

    Bare mode uses an empty directory like strict mode, but runs with
  the invoking user's credentials.  It is inferior to strict mode, but
  can be used for NFS-mounted home directories, since NFS does not
  support id-mapped mounts.

`-n` *name*, `--name` *name*
: jai allows you to have multiple sandboxed home directories, which
  may be useful when sandboxing multiple tools that should not have
  access to each other's API keys.  This option specifies which home
  directory to use.  If no such sandbox exists yet, it will be created
  on demand.  When not specified, the default is just `default`.  Note
  that each name can be associated with both a casual home directory
  (accessible at `/run/jai/$USER/`*name*`.home`, with changes in
  `$HOME/.jai/`*name*`.changes`) and a strict/bare home directory (in
  `$HOME/.jai/`*name*`.home`).  There is no special relation between
  these home directories, but casual and strict sandboxes by the same
  name do share the same `/tmp` directory.

`--mask` *file*
: When creating an overlay home directory, create a "whiteout" file to
  hide *file* in the jail.  *file* must be a relative path and is
  relative to your home directory.  You can specify this option
  multiple times.  An easier way to hide files is just to delete them
  from `/run/jai/$USER/*.home`; hence, this option is mostly useful in
  configuration files to specify a set of files to delete by default.
  If you add `mask` directives to your configuration file, you will
  need to clear mounts with `jai -u` before the changes take effect.

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
: Filters *var* from the environment of the sandboxed program.  Can be
  the simple name of an environment variable, or can use the wildcard
  `*` as in `*_PID`.  (Since sandboxed processes don't see outside
  processes, you might as well filter any PIDs exposed in environment
  variables to avoid confusion.)

`--setenv` *var*, `--setenv` *var*`=`*value*
: There are two forms of this command.  If the argument does not
  contain `=`, then `--setenv` reverses the effect of `--unsetenv`
  *var*.  If *var* is a pattern, it must exactly match the unset
  pattern you want to remove.  For example, `--unsetenv=*_PASSWORD
  --setenv=IPMI_PASSWORD` and `--unsetenv=*_PASSWORD
  --setenv=IPMI_PASSWORD` will both pass the `IPMI_PASSWORD`
  environment variable through to the jail, while
  `--unsetenv=*_PASSWORD --setenv=IPMI_*` will not.

    If the argument contains `=`, then *var* is always treated as a
  variable, not a pattern, and it is assigned *value* in the jail.

`--storage` *dir*
: Specify an alternate location in which to store private home
  directories and overlays.  The default is $JAI_CONFIG_DIR or
  $HOME/.jai, but if your home directory is on NFS you may wish to use
  storage on a local file system, as NFS does not support the extended
  attributes required by overlay file systems and does not support
  id-mapped mounts.

`--command` *bash-command*
: jai launches the sandboxed program you specify by running
  "`/bin/bash -c` *bash-command* *cmd* *arg*...".  By default,
  *bash-command* just runs the program as `"$0" "$@"`, but in
  configuration files for particular programs, you can use
  *bash-command* to set environment variables or add additional
  command-line options.

`-u`
: Unmounts all overlay directories from `/run/jai` and cleans up
  overlay-related files in `$HOME/.jai/*.work` that the user might not
  be able to clean up without root.  This option also destroys the
  private `/tmp` and `/var/tmp` directories (same directory at both
  mount points), so make sure you don't need anything in there.

  Many configuration choices apply only when a sandbox is first
  created, so you must run `jai -u` to change them.  In particular,
  you must use this option if you have added new files to be masked,
  as masking only takes effect at the time an overlay home is created.

`--print-defaults`
: Prints the default contents for `$HOME/.jai/.defaults`.

`--version`
: Prints the version number and copyright.

# ENVIRONMENT

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

`JAI_NAME`
: Set to the name of the jai instance (specified by `-n` or `--name`)
  inside the jail.

`JAI_MODE`
: Set to the mode (strict, bare, or casual) inside a jail.

# FILES

In the following paths, the location `$HOME/.jai` can be changed by
setting the `JAI_CONFIG_DIR` environment variable.

`$HOME/.jai/default.conf`, `$HOME/.jai/`*cmd*`.conf`
: Configuration file if none is specified with `-C`.  If there is a
  file for *cmd*, then *cmd*`.conf` is used.  Otherwise `default.conf`
  is used.

`$HOME/.jai/.defaults`
: Reasonable system defaults to be included in `defaults.conf` or
  *cmd*`.conf`.  This file is created automatically by jai.  The file
  has no effect if you don't include it, but you should probably begin
  all configuration files with the line `conf .defaults` to get the
  defaults.

`$HOME/.jai/default.changes`, `$HOME/.jai/`*name*`.changes`
: This "upper" directory is overlaid on your home directory and
  contains changes that have been made inside a casual jail.  If you
  make changes in this directory, you may need to tear down and
  recreate the sandboxed home directory with `jai -u`.  The
  non-default version is used when you specify `-n` *name* on the
  command line.  If you specified `--storage=`*dir*, the changes
  directory will be in *dir* instead of `$HOME/.jai`.

`$HOME/.jai/default.work`, `$HOME/.jai/`*name*`.work`
: This "work" directory is required by overlayfs, but does not contain
  anything user-accessible.  Every once in a while the overlay file
  system may create files in here that you cannot delete.  If you are
  trying to blow away an overlay directory to start from scratch and
  cannot delete this directory, try running `jay -u` which will clean
  things up.  If you specified `--storage=`*dir*, or used a symbolic
  link for your changes directory, then the work directory will always
  be next to the changes directory wherever that lives.

`$HOME/.jai/default.home`, `$HOME/.jai/`*name*`.home`
: Private home directory for bare and strict jails.  If you specified
  `--storage=`*dir*, the these directories will be in *dir* instead.

`/run/jai/$USER/default.home`, `/run/jai/$USER/`*name*`.home`
: Home directories for casual jails.  You can delete files with
  sensitive data in these jail directories to hide theme from jailed
  processes, or see the `--mask` option.

`/run/jai/$USER/tmp/default`, `/run/jai/$USER/tmp/`*name*
: Private `/tmp` and `/var/tmp` directory (they are the same) in
  jails.

# BUGS

Overlayfs needs an empty directory `$HOME/.jai/work`, into which it
places two root-owned directories `index` and `work`.  Usually these
directories are empty when the file system is unmounted.  However,
occasionally they contain files, in which case it requires root
privileges to delete the directories.  You can run `jai -u` to clean
these up if you are unable to delete them.

In general overlayfs can be flaky.  If the attributes on the
`default.changes` directory get out of sync, it may require making a
new `default.changes` directory to get around mounting errors.
