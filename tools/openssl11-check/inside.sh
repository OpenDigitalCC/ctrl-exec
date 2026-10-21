#!/bin/bash
# Runs inside the check container: the tree is at /src (root-owned, from
# git archive). Copy it to the unprivileged tester's home and run prove there
# as that user, as the suite runs on a development host. Arguments: test files.
set -euo pipefail

echo "openssl:     $(openssl version)"
perl -MNet::SSLeay -MIO::Socket::SSL -e \
    'printf "Net::SSLeay: %s (library %s)\nIO::Socket::SSL: %s\n", $Net::SSLeay::VERSION,
         Net::SSLeay::SSLeay_version(0), $IO::Socket::SSL::VERSION'
cp -a /src /home/tester/src
chown -R tester:tester /home/tester/src
cd /home/tester/src
exec runuser -u tester -- prove -Ilib "$@"
