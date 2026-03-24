
#include "jai.h"

const std::string jai_defaults =
    R"(# This file contains generic defaults built into jai.  It is intended
# to be included by other configuration files with a line:
#
#     conf .defaults
#
# You can override settings in this file by editing it directly or by
# appending configuration directives to default.conf or other
# <name>.conf files after the `conf .defaults` line.  (Later lines
# override previous ones in configuration files.)
#
# If you delete this file, jai will re-create it the next time it
# runs.  You can also see the default contents of this file by running
#
#     jai --print-defaults


# By default, jai stores private home directory state in $HOME/.jai
# (or in $JAI_CONFIG_DIR, if set).  However, jai works best if the
# storage directory is not on NFS.  If your home directory is on NFS,
# use a `storage` directive to specify a local storage location.
# Environment variables named in ${...} will be substituted.  The
# storage directory will automatically be organized into per-sandbox
# subdirectories, so most configurations should use the sandbox
# location.

# storage /some/local/directory/${JAI_USER}/.jai

# The default mode is strict.  A strict jail runs under the dedicated
# jai UID and starts with an empty home directory.  A casual jail runs
# with your own UID and makes your home directory copy-on-write via an
# overlay mount.  Strict mode cannot grant unrestricted access to
# directories on NFS file systems.  You will have to use bare mode
# (which gives you a bare home directory, but still runs with your
# UID) to expose NFS directories.  Uncomment any of the following to
# set the mode, or override it in individual .jail files:

# mode casual
# mode bare
# mode strict

# You can use "jail NAME" to specify different jails.  For casual
# jails, the home directory will be in /run/jai/$USER/NAME.home, and
# changed files will be in $HOME/.jai/NAME.changes.  For strict jails,
# the home directory will be $HOME/.jai/NAME.home.  If you leave jail
# undefined, the name will be "default" and the mode will default to
# casual, but if you define this to anything including "default", then
# the default mode will be strict.

# jail default

# jai launches jailed programs by running bash with the command name
# in "$0" and the arguments in "@".  Altering command allows you set
# environment variables dynamically or add command-line arguments,
# which is more useful to do in a non-default configuration file.

# command "$0" "$@"

# Masked files are deleted when an overlayfs is first created, but
# have no effect on existing overlays or on strict/bare jails.  To
# delete files from an existing overlay, delete them under
# /run/jai/$USER/default.home.  Otherwise, to apply new mask
# directives after editing this file, you can run "jai -u" to unmount
# any existing overlays.  If you want to avoid masing any of these
# files in one particular configuration, you can use a directive such
# as `unmask .aws` to undo the effects from a previously included
# default file.

mask .jai
mask .ssh
mask .gnupg
mask .local/share/keyrings
mask .netrc
mask .git-credentials
mask .aws
mask .azure
mask .config/gcloud
mask .config/gh
mask .config/Keybase
mask .config/kube
mask .docker
mask .password-store
mask .mozilla
mask .config/BraveSoftware
mask .config/chromium
mask .config/google-chrome
mask .config/mozilla-chrome
mask .bash_history
mask .zsh_history

# The following environment variables will be removed from jail
# environments.  You can use * as a wildcard to match any variables
# matching the pattern.  If you want to undo any of these unsetenv
# commands in a particular config file, you can use setenv to reverse
# the effects of unsetenv.

unsetenv *_ACCESS_KEY
unsetenv *_APIKEY
unsetenv *_API_KEY
unsetenv *_AUTH
unsetenv *_AUTH_TOKEN
unsetenv *_CONNECTION_STRING
unsetenv *_CREDENTIAL
unsetenv *_CREDENTIALS
unsetenv *_PASSWD
unsetenv *_PASSWORD
unsetenv *_PID
unsetenv *_PRIVATE_KEY
unsetenv *_PWD
unsetenv *_SECRET
unsetenv *_SECRET_KEY
unsetenv *_SOCK
unsetenv *_SOCKET
unsetenv *_SOCKET_PATH
unsetenv *_TOKEN
unsetenv AZURE_CLIENT_ID
unsetenv AZURE_TENANT_ID
unsetenv BB_AUTH_STRING
unsetenv DATABASE_URL
unsetenv GOOGLE_APPLICATION_CREDENTIALS
unsetenv KUBECONFIG
unsetenv MAIL
unsetenv MONGODB_URI
unsetenv MONGO_URI
unsetenv REDIS_URL
unsetenv SENTRY_DSN
unsetenv SLACK_WEBHOOK_URL

# The following environment variables get set in sandboxes.  You can
# substitute existing environment variables (before any
# unsetenv/setenv have been applied) by including them in ${...}.  You
# can reference ${JAI_USER} here, which gets set before configuration,
# but not ${JAI_JAIL} or ${JAI_MODE}, which are set after.

setenv USER=${JAI_USER}
setenv LOGNAME=${JAI_USER}
)";

extern const std::string default_conf =
  R"(# The following line includes sensible defaults from the file
# .defaults.  You can override these defaults by appending
# configuration options to this file.  See the .defaults file or the
# jai(1) man page for details.

conf .defaults

)";

extern const std::string default_jail =
  R"(# Set casual mode for the default jail.

mode casual

)";
