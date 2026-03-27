#!/bin/sh

. ./common.sh

setup_test basic
init_config

assert_path_exists "$CONFIG_DIR/.defaults"
assert_path_exists "$CONFIG_DIR/default.conf"
assert_path_exists "$CONFIG_DIR/default.jail"

capture run_jai --version
assert_status 0
assert_contains "$CAPTURE_STDOUT" "Untrusted user for strict mode:"
assert_contains "$CAPTURE_STDOUT" "This program comes with NO WARRANTY"

capture run_jai --print-defaults
assert_status 0
cmp -s "$CONFIG_DIR/.defaults" "$CAPTURE_OUT_FILE" ||
  fail "--print-defaults output does not match .defaults"

cat >"$CONFIG_DIR/alt.conf" <<'EOF'
conf .defaults
mode bare
jail alt-name
command /usr/bin/env
EOF

capture run_jai -D -C alt
assert_status 0
assert_contains "$CAPTURE_STDOUT" "JAI_MODE=bare"
assert_contains "$CAPTURE_STDOUT" "JAI_JAIL=alt-name"
