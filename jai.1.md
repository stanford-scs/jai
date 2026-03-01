% jai(1)
% David Mazieres
%

# NAME

jai - Jail an AI agent

# SYNOPSIS

`jai` [`-d` *dir*] [`-D`] *cmd* [*arg* ...] \
`jai` \
`jai` `-u`

# DESCRIPTION

`jai` is a super lightweight sandbox for AI agents requiring almost no
configuration.  It provides only casual security, so is not a
substitute for using a proper container to confine agents.  However,
it is a great alternative to using no protection when you are thinking
of giving an agent full control of your account and all its files.
Compared to the latter, `jai` can reduce the blast radius should
things go wrong.

Before using `jai`, if your home directory is on NFS, make
`$HOME/.jai` a symbolic link to a directory you own on a local file
system supporting extended attributes.

To get started, run `jai` with no arguments.  (If it is not setuid
root, you will need to run `sudo jai`.)  This will create an overlay
mount of your home directory in `/run/jai/$USER/sandboxed-home`.
Change to that directory and delete any sensitive files you don't want
your agent to have access to.  (Start with deleting a file you don't
care about, and verify that it only disappears from the sandbox, not
from your real home directory.)

Once you are satisfied with the sandbox, go to a project directory you
own and run `jai $SHELL`.  That will let you explore the sandboxed
environment.  You have complete access to the directory in which you
ran `jai`, but the rest of your home directory is sandboxed (changes
will not affect your real home directory), and the rest of the file
system outside your home directory is read-only.  If that works, exit
your shell and run `jai` _code-assistant_ for your favorite code
assistant.

If you forget to export some directory that you wanted the sandboxed
tool to update, you will find changed files in `$HOME/.jai/changes`.
You can destroy the sandbox with `jai -u`, move the changed files back
into your home directory, and re-run `jai` with the appropriate `-d`
flag.

# EXAMPLES

    jai -d ~/.claude claude

    jai -d ~/.codex codex

    mkdir -p ~/.local/share/opencode
    jai -d ~/.config/opencode -d ~/.local/share/opencode opencode

# OPTIONS

`-d` *dir*
: Grant full access to directory *dir* and everything below in the
  jail.  You must own the directory.  You can supply this option
  multiple times.

`-D`
: By default, `jai` grants access to the current working directory
  even if it is not specified with `-d`.  This option suppresses that
  behavior.  If you run with `-D` and no `-d` options, your entire
  home directory will be copy-on-write and nothing will be directly
  exported.

`-u`
: Removes the sandboxed home directory from `/run/jai`.  This also
  destroys the private `/tmp` and `/var/tmp` directory (same directory
  at both mount points), so make sure you don't need anything in
  there.

# ENVIRONMENT

`SUDO_USER`, `USER`
: If run with real UID 0 and either of these environment variables
  exists, it will be taken as the user whose home directory should be
  sandboxed.  This makes it convenient to run `jai` via `sudo` if you
  don't want to install it setuid root.  If both are set, `SUDO_USER`
  takes precedence.

# FILES

`$HOME/.jai`
: `jai` uses this to construct an overlay mount so that sandboxed code
  can believe it is writing to your home directory without actually
  doing so.  This directory requires extended attributes, so **must
  not be on NFS**.  Make it a symbolic link to a local directory owned
  by you if your home directory is on NFS.

`$HOME/.jai/changes`
: This "upper" directory is overlaid on your home directory and
  contains changes that have been made inside a jail.  If you make
  changes in this directory, you may need to tear down and recreate
  the sandboxed home directory with `jai -u`.

`/run/jai/$USER/sandboxed-home`
: Sandboxed home directory for jails.  You should delete any files
  with sensitive data in this directory so they will not be available
  in the jail.

`/run/jai/$USER/tmp`
: Private `/tmp` and `/var/tmp` directory made available in the jail.

# BUGS

Overlayfs needs an empty directory `$HOME/.jai/work`, into which it
places two root-owned directories `index` and `work`.  Usually these
directories are empty when the file system is unmounted.  However,
occasionally they contain files, in which case it requires root
privileges to delete the directories.  (A user can still move
`$HOME/.jai/work` out of the way if `jai` won't restart, but it's
annoying not to be able to clean up completely without root.)

In general overlayfs can be flaky.  If the attributes on the `changes`
directory get out of sync, it may require making a new `changes`
directory to get around mounting errors.

The initial file blacklist is hard-coded, but should support a
configuration file.

`jai` removes a few hard-coded environment variables and suffixes,
such as anything ending `_PID`, `_SOCK`, or `_TOKEN`, or `_PASSWORD`,
but otherwise requires a wrapper to clean the environment if you are
in the habit of storing secrets there.  If you actually want to pass
these environment variables through, you will have to launder them
through some other variable name.  There should be a configuration
file.

There is only one sandboxed home directory per user, so if you run
multiple sandboxed agents, they will have access to each other's
credentials unless you pass through the directory with `-d`.
