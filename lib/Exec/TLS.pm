package Exec::TLS;

use strict;
use warnings;

# Shared TLS hardening for every ctrl-exec listener and client, so the policy
# cannot drift between endpoints. Returns a flat list of IO::Socket::SSL
# options to splice into a ->new() or set_defaults() call:
#
#   - SSL_version: negotiate TLS 1.2 or 1.3 only; SSLv2/SSLv3/TLS1.0/1.1 are
#     disabled explicitly rather than relying on the system OpenSSL policy.
#   - SSL_cipher_list (TLS 1.2): ECDHE + AES-GCM only. No CBC, RC4, export,
#     or anonymous suites.
#   - SSL_ciphersuites (TLS 1.3): AEAD suites only.
sub hardening {
    return (
        SSL_version      => 'SSLv23:!SSLv2:!SSLv3:!TLSv1:!TLSv1_1',
        SSL_cipher_list  => 'ECDHE-RSA-AES256-GCM-SHA384:'
                          . 'ECDHE-ECDSA-AES256-GCM-SHA384:'
                          . 'ECDHE-RSA-AES128-GCM-SHA256:'
                          . 'ECDHE-ECDSA-AES128-GCM-SHA256',
        SSL_ciphersuites => 'TLS_AES_256_GCM_SHA384:'
                          . 'TLS_CHACHA20_POLY1305_SHA256:'
                          . 'TLS_AES_128_GCM_SHA256',
    );
}

1;
