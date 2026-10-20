package NoSyslog;
# Loaded with -MNoSyslog into a test agent so Exec::Log stays on its stderr
# fallback instead of opening syslog, and the test can read the agent's log.
use strict;
use warnings;
use Exec::Log ();
{ no warnings 'redefine'; *Exec::Log::init = sub { 1 }; }
1;
