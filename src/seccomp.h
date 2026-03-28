// -*-C++-*-

#pragma once

// Install a seccomp-bpf filter that blocks dangerous syscalls.
// Must be called after all privileged setup is complete (credentials
// dropped, namespaces entered) and just before exec.
//
// The filter uses an allowlist approach for the most dangerous
// syscalls while permitting everything else.  This is deliberately
// not a full allowlist of all syscalls (which would break too many
// programs) but rather a denylist of syscalls that have no legitimate
// use inside a sandbox.
void install_seccomp_filter();
