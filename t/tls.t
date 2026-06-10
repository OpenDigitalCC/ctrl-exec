#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::TLS qw();

# The shared TLS hardening applied to every ctrl-exec listener and client.
my %h = Exec::TLS::hardening();

# --- version floor: TLS 1.2/1.3 only ---

ok exists $h{SSL_version}, 'hardening sets SSL_version';
like $h{SSL_version}, qr/!SSLv3/,   'SSL_version disables SSLv3';
like $h{SSL_version}, qr/!TLSv1\b/, 'SSL_version disables TLS 1.0';
like $h{SSL_version}, qr/!TLSv1_1/, 'SSL_version disables TLS 1.1';

# --- cipher policy: AEAD only, no legacy ---

ok exists $h{SSL_cipher_list},  'hardening sets SSL_cipher_list (TLS 1.2)';
ok exists $h{SSL_ciphersuites}, 'hardening sets SSL_ciphersuites (TLS 1.3)';

like $h{SSL_cipher_list}, qr/ECDHE/,     'TLS 1.2 ciphers are ECDHE (forward secrecy)';
like $h{SSL_cipher_list}, qr/GCM/,       'TLS 1.2 ciphers are AES-GCM (AEAD)';
unlike $h{SSL_cipher_list}, qr/CBC/i,    'no CBC ciphers';
unlike $h{SSL_cipher_list}, qr/RC4/i,    'no RC4 ciphers';
unlike $h{SSL_cipher_list}, qr/\bNULL\b|aNULL|eNULL/i, 'no NULL/anonymous ciphers';

like $h{SSL_ciphersuites}, qr/TLS_AES_256_GCM_SHA384/, 'TLS 1.3 AEAD suite present';

done_testing;
