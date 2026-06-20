#!/usr/bin/perl
# t/pairing-queue-limit.t
#
# Unit tests for the pairing queue depth limit (Item 10).
#
# _handle_pair_request currently uses a file-scoped lexical $PAIRING_DIR
# that cannot be overridden from outside the package. The queue limit
# subtests require a small source change to make the function testable:
# pass pairing_dir as a fifth parameter (see NOTE at end of file).
#
# Until that change is applied, the queue limit subtests detect the
# situation and skip gracefully. The run_pairing_mode parameter test
# runs unconditionally.

use strict;
use warnings;
use Test::More;
use File::Temp  qw(tempdir);
use JSON        qw(encode_json decode_json);
use FindBin     qw($Bin);
use lib         "$Bin/../lib";

use Exec::Pairing qw();
use Exec::Log     qw();

Exec::Log::init('test');
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub {};
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub make_pair_request {
    my (%opts) = @_;
    my $hostname = $opts{hostname} // 'test-agent';
    my $body = encode_json({
        hostname => $hostname,
        csr      => "-----BEGIN CERTIFICATE REQUEST-----\nYQ==\n-----END CERTIFICATE REQUEST-----\n",
        nonce    => 'aabbccddaabbccdd',
    });
    return "POST /pair HTTP/1.0\r\n"
         . "Content-Type: application/json\r\n"
         . "Content-Length: " . length($body) . "\r\n"
         . "\r\n"
         . $body;
}

# Run _handle_pair_request with a mock socketpair.
# Returns decoded JSON response sent back to the client side.
# pairing_dir is passed as the optional fifth argument if provided.
#
# auto_deny => 1: forks a background process that watches pairing_dir for a
# newly queued .json file and immediately writes a .denied response. This
# unblocks _handle_pair_request's poll loop in ~2 seconds, allowing tests
# that verify a request was accepted (file written) to complete without
# waiting the full 10-minute poll timeout.
sub call_handle {
    my (%opts) = @_;
    my $max_queue   = $opts{max_queue}   // 10;
    my $pairing_dir = $opts{pairing_dir};
    my $request     = $opts{request}     // make_pair_request();
    my $log_ref     = $opts{log_ref}     // [];
    my $auto_deny   = $opts{auto_deny}   // 0;

    my $log_fn = sub { push @$log_ref, $_[0] };

    require IO::Socket::UNIX;
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0,
    ) or die "socketpair: $!";

    print $client $request;
    $client->shutdown(1);

    # Background denier: watches for any new .json in pairing_dir and writes
    # a .denied file so the poll loop exits promptly.
    my $denier_pid;
    if ($auto_deny && defined $pairing_dir) {
        my @existing = glob("$pairing_dir/*.json");
        my %known = map { $_ => 1 } @existing;
        $denier_pid = fork();
        die "fork: $!" unless defined $denier_pid;
        if ($denier_pid == 0) {
            require JSON;
            for (1..15) {  # poll up to 30 seconds
                sleep 2;
                for my $f (glob("$pairing_dir/*.json")) {
                    next if $known{$f};
                    (my $base = $f) =~ s/\.json$//;
                    unless (-f "$base.denied") {
                        open my $fh, '>', "$base.denied" or next;
                        print $fh JSON::encode_json({ status => 'denied', reason => 'test-auto-deny' });
                    }
                }
            }
            exit 0;
        }
    }

    if (defined $pairing_dir) {
        Exec::Pairing::_handle_pair_request(
            $server, '127.0.0.1', $log_fn, $max_queue, $pairing_dir
        );
    } else {
        Exec::Pairing::_handle_pair_request(
            $server, '127.0.0.1', $log_fn, $max_queue
        );
    }
    $server->close;

    if (defined $denier_pid) {
        kill 'TERM', $denier_pid;
        waitpid $denier_pid, 0;
    }

    local $/;
    my $raw = <$client> // '';
    $client->close;
    # Strip all HTTP response chunks up to the last \r\n\r\n separator.
    # _handle_pair_request sends two responses for accepted requests:
    # first {"status":"pending",...} then the deny/approve response.
    # Take the final JSON object only.
    my @chunks;
    while ($raw =~ s/\A.*?\r\n\r\n//s) {
        push @chunks, $raw =~ /\A(\{.*?\})/s ? $1 : '';
    }
    my $body = $chunks[-1] // $raw;
    $body = $raw unless $body =~ /\{/;
    return eval { decode_json($body) } // { _raw => $raw };
}

# Pre-populate pairing dir with N .json queue files.
# stale => N makes the first N files 700 seconds old so _expire_stale_requests
# will remove them.
sub populate_queue {
    my ($dir, $n, %opts) = @_;
    my $stale = $opts{stale} // 0;
    for my $i (1..$n) {
        my $id   = sprintf('%016x', $i);
        my $path = "$dir/${id}.json";
        open my $fh, '>', $path or die "Cannot write $path: $!";
        print $fh encode_json({
            id => $id, hostname => "host-$i", ip => '127.0.0.1',
            csr => 'x', nonce => '', received => '',
        });
        close $fh;
        if ($i <= $stale) {
            my $old = time() - 700;
            utime $old, $old, $path;
        }
    }
}

# Detect whether _handle_pair_request accepts a pairing_dir 5th argument
# by inspecting the source.
my $has_pairing_dir_param = do {
    my $src = "$Bin/../lib/Exec/Pairing.pm";
    if (-f $src) {
        open my $fh, '<', $src or die $!;
        local $/; my $text = <$fh>;
        $text =~ /sub _handle_pair_request\s*\{\s*my\s*\([^)]*\$pairing_dir\b/s ? 1 : 0;
    } else { 0 }
};

my $skip_reason = '_handle_pair_request does not accept pairing_dir - see NOTE at end of file';

# ---------------------------------------------------------------------------
# Test 1: queue at limit - request rejected
# ---------------------------------------------------------------------------

SKIP: {
    skip $skip_reason, 3 unless $has_pairing_dir_param;

    my $dir = tempdir(CLEANUP => 1);
    populate_queue($dir, 10);
    my @logs;
    my $resp = call_handle(max_queue => 10, pairing_dir => $dir, log_ref => \@logs);

    subtest 'queue at limit: status is error' => sub {
        is $resp->{status}, 'error', 'response status is error';
        like $resp->{reason} // '', qr/queue full/i, 'reason mentions queue full';
    };

    subtest 'queue at limit: no new file written' => sub {
        my @files = glob("$dir/*.json");
        is scalar @files, 10, 'still 10 files - no new file written';
    };

    subtest 'queue at limit: pair-reject logged with REASON=queue-full' => sub {
        my @rejects = grep { ($_->{ACTION} // '') eq 'pair-reject' } @logs;
        is scalar @rejects, 1,               'one pair-reject log entry';
        is $rejects[0]{REASON}, 'queue-full', 'REASON is queue-full';
        is $rejects[0]{IP},     '127.0.0.1',  'IP logged correctly';
    };
}

# ---------------------------------------------------------------------------
# Test 2: one below limit - request accepted, file written
# ---------------------------------------------------------------------------

SKIP: {
    skip $skip_reason, 3 unless $has_pairing_dir_param;

    my $dir = tempdir(CLEANUP => 1);
    populate_queue($dir, 9);
    my @logs;
    my $resp = call_handle(max_queue => 10, pairing_dir => $dir, log_ref => \@logs, auto_deny => 1);

    subtest 'queue at 9/10: request accepted' => sub {
        isnt $resp->{status}, 'error', 'response is not an error';
    };

    subtest 'queue at 9/10: 10th file written' => sub {
        my @files = glob("$dir/*.json");
        is scalar @files, 10, '10 files present after accepted request';
    };

    subtest 'queue at 9/10: no pair-reject logged' => sub {
        my @rejects = grep { ($_->{ACTION} // '') eq 'pair-reject' } @logs;
        is scalar @rejects, 0, 'no pair-reject log entry for accepted request';
    };
}

# ---------------------------------------------------------------------------
# Test 3: 10 files, 5 stale - stale expiry clears space, request accepted
# ---------------------------------------------------------------------------

SKIP: {
    skip $skip_reason, 1 unless $has_pairing_dir_param;

    my $dir = tempdir(CLEANUP => 1);
    populate_queue($dir, 10, stale => 5);
    my $resp = call_handle(max_queue => 10, pairing_dir => $dir, auto_deny => 1);

    subtest 'queue with 5 stale: expires stale entries and accepts request' => sub {
        isnt $resp->{status}, 'error',
            'request accepted after stale expiry frees space';
        my @files = glob("$dir/*.json");
        # 5 fresh survive expiry + 1 new written = 6
        is scalar @files, 6, '6 files present (5 survived expiry + 1 new)';
    };
}

# ---------------------------------------------------------------------------
# Test 4: custom max_queue enforced
# ---------------------------------------------------------------------------

SKIP: {
    skip $skip_reason, 2 unless $has_pairing_dir_param;

    my $dir_full = tempdir(CLEANUP => 1);
    populate_queue($dir_full, 3);
    my $resp_full = call_handle(max_queue => 3, pairing_dir => $dir_full);

    subtest 'custom max_queue=3: rejected at 3 files' => sub {
        is $resp_full->{status}, 'error', 'rejected when queue at custom limit';
    };

    my $dir_ok = tempdir(CLEANUP => 1);
    populate_queue($dir_ok, 2);
    my $resp_ok = call_handle(max_queue => 3, pairing_dir => $dir_ok, auto_deny => 1);

    subtest 'custom max_queue=3: accepted with 2 files' => sub {
        isnt $resp_ok->{status}, 'error', 'accepted when below custom limit';
        my @files = glob("$dir_ok/*.json");
        is scalar @files, 3, '3 files after accepted request';
    };
}

# ---------------------------------------------------------------------------
# run_pairing_mode: max_queue parameter accepted without croak
# ---------------------------------------------------------------------------

subtest 'run_pairing_mode: accepts max_queue parameter' => sub {
    # Verify max_queue is accepted as a valid parameter.
    # Pass no cert/key so run_pairing_mode croaks on the 'cert required'
    # guard before reaching any I/O. The test only checks that the croak
    # is not about max_queue being unknown.
    eval {
        Exec::Pairing::run_pairing_mode(
            max_queue => 20,
            log_fn    => sub {},
        );
    };
    unlike $@, qr/unknown.*max_queue|invalid.*max_queue|unexpected.*max_queue/i,
        'max_queue parameter accepted without error';
};

# ---------------------------------------------------------------------------
# Body size cap (SEC-001): the unauthenticated pairing port must reject an
# oversized declared Content-Length BEFORE reading the body, or a hostile
# client can force the child to buffer arbitrary memory.
# ---------------------------------------------------------------------------

subtest 'oversized Content-Length is rejected before the body is read' => sub {
    my $dir = tempdir(CLEANUP => 1);
    # Declare a body far larger than the 64 KiB cap but send only a few bytes;
    # the handler must reject on the header alone and never block reading 200 MB.
    my $request = "POST /pair HTTP/1.0\r\n"
                . "Content-Type: application/json\r\n"
                . "Content-Length: 209715200\r\n"
                . "\r\n"
                . "{}";
    my $log_ref = [];
    my $resp = call_handle(
        request     => $request,
        pairing_dir => $dir,
        log_ref     => $log_ref,
    );
    is $resp->{status}, 'error', 'oversized request gets an error response';
    is $resp->{reason}, 'request too large', 'reason names the size cap';
    ok !glob("$dir/*.json"), 'no request was queued';
    ok( (grep { ($_->{REASON} // '') eq 'body-too-large' } @$log_ref),
        'rejection is logged as body-too-large' );
};

# ---------------------------------------------------------------------------
# NOTE: _handle_pair_request accepts pairing_dir as a fifth parameter and
# run_pairing_mode passes $PAIRING_DIR to it. This was the change required
# to make the queue limit subtests testable without touching the real
# pairing directory. The public API is unaffected.
# ---------------------------------------------------------------------------

done_testing;
