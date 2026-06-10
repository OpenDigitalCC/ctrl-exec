#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);
use File::Path qw(make_path);

# Exercises install.sh's install_lib() in isolation by sourcing the script
# (which defines the helpers but does not run main when sourced) and calling
# install_lib() against throwaway source and target directories.
#
# Regression guard for the bug where install_lib copied lib/ but never the
# VERSION file, so Exec::API reported "version":"unknown" on every installed
# system (the VERSION file is read at runtime from $LIB_DIR/VERSION).

my $install_sh = "$Bin/../install.sh";
ok(-f $install_sh, 'install.sh present');

# Run install_lib() against the given source/target dirs and return the
# child exit status. PKG_MGR is forced to apt so the OpenWRT JSON shim
# branch is skipped.
sub run_install_lib {
    my ($src, $dst) = @_;
    my $script = <<"END";
set -euo pipefail
source "$install_sh"
SOURCE_DIR="$src"
LIB_DIR="$dst"
PKG_MGR="apt"
install_lib >/dev/null
END
    return system('bash', '-c', $script);
}

# --- VERSION file present in source: copied to the library dir ---
{
    my $src = tempdir(CLEANUP => 1);
    my $dst = tempdir(CLEANUP => 1);
    make_path("$src/lib/Exec");
    write_file("$src/lib/Exec/Dummy.pm", "package Exec::Dummy; 1;\n");
    write_file("$src/VERSION", "9.9.9-test\n");

    is(run_install_lib($src, $dst), 0, 'install_lib succeeds when VERSION present');

    ok(-f "$dst/VERSION", 'VERSION file installed to $LIB_DIR/VERSION');
    is(slurp("$dst/VERSION"), "9.9.9-test\n", 'installed VERSION matches source');
    ok(-f "$dst/Exec/Dummy.pm", 'library modules copied alongside VERSION');

    my $mode = (stat "$dst/VERSION")[2] & 07777;
    is($mode, 0644, 'installed VERSION is mode 0644');
}

# --- VERSION file absent in source (dev checkout): no-op, no failure ---
{
    my $src = tempdir(CLEANUP => 1);
    my $dst = tempdir(CLEANUP => 1);
    make_path("$src/lib/Exec");
    write_file("$src/lib/Exec/Dummy.pm", "package Exec::Dummy; 1;\n");

    is(run_install_lib($src, $dst), 0, 'install_lib succeeds when VERSION absent');
    ok(!-e "$dst/VERSION", 'no VERSION installed when source has none');
    ok(-f "$dst/Exec/Dummy.pm", 'library modules still copied');
}

done_testing;

sub write_file {
    my ($path, $content) = @_;
    open my $fh, '>', $path or die "open $path: $!";
    print {$fh} $content;
    close $fh;
}

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or die "open $path: $!";
    local $/;
    return <$fh>;
}
