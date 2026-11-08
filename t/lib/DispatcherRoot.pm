package DispatcherRoot;
# Loaded with -MDispatcherRoot into a test dispatcher (ced) subprocess so it
# looks for its config directories under CE_TEST_DISPATCHER_ROOT instead of the
# host's /etc: a host with ctrl-exec installed must not change what the test
# sees. Without the variable nothing changes.
use strict;
use warnings;
use Exec::DispatcherConfig ();
if (defined(my $r = $ENV{CE_TEST_DISPATCHER_ROOT})) {
    $Exec::DispatcherConfig::CONF_DIR   = "$r/etc/ctrl-exec-dispatcher";
    $Exec::DispatcherConfig::LEGACY_DIR = "$r/etc/ctrl-exec";
}
1;
