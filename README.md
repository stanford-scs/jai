![](./logo.svg "JAI logo")

# JAI - An ultra lightweight jail for AI CLIs on modern linux

`jai` strives to be the easiest container in the world to
configure--so easy that you never again need to run a code assistant
without protection.  It's not a substitute for
[docker](https://www.docker.com/) or [podman](https://podman.io/) when
you need better isolation.  But if you regularly do risky things like
run an AI CLI with your own privileges in your home directory on a
computer that you care about, then `jai` could reduce the damage when
things go wrong.

`jai` *command* runs *command* with the following policy:

* *command* has complete access to the current working directory.

* *command* has copy-on-write access to the rest of your home
  directory.  It can write there to store dot files, but the changes
  will be kept separate in a `changes` directory and will not actually
  modify your real home directory.

* */tmp* and */var/tmp* are private.

* The rest of the file system is read only (though devices are still
  accessible).

With command-line options or configuration, `jai` supports the
following:

* A "strict" mode where jailed processes start with an empty home
  directory and a different user id, so can read fewer sensitive
  files.

* The ability to grant access to other directories besides your
  current working directory.

* Multiple named sandboxed home directories that do not see each
  other's changes.

* Per-command configuration files.

jai emphasizes security over portability.  It heavily leverages modern
linux APIs to isolate processes and avoid time-of-check-to-time-of-use
race conditions.  It will not work with kernels older than 6.13 or
operating systems other than linux.

See the [home page](https://jai.scs.stanford.edu) or the [man
page](jai.1.md) for more documentation.

See the [INSTALL](INSTALL) file for installation instructions.
