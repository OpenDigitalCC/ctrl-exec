package Exec::Log;

use strict;
use warnings;
use Sys::Syslog qw(openlog syslog closelog);

# Define priority/facility constants numerically to avoid import issues
use constant { _LOG_INFO => 6, _LOG_WARNING => 4, _LOG_ERR => 3, _LOG_DAEMON => 24 };
use Carp qw(croak);


my $ident = 'ctrl-exec';
my $opened = 0;

# Call once at startup: init('ctrl-exec-agent') or init('ctrl-exec-dispatcher')
sub init {
    my ($program_name) = @_;
    croak "program name required" unless $program_name;
    $ident = $program_name;
    openlog($ident, 'pid,ndelay', _LOG_DAEMON);
    $opened = 1;
}

# Write a structured syslog line from a hashref of key=value pairs
# log_action(INFO, { ACTION => 'run', SCRIPT => 'backup', EXIT => 0, ... })
sub log_action {
    my ($level, $fields) = @_;

    croak "log_action: fields must be a hashref" unless ref $fields eq 'HASH';
    croak "log_action: ACTION field required"    unless exists $fields->{ACTION};

    my $priority = _level($level);

    # Build deterministic key order: ACTION first, then alphabetical
    my $msg = join ' ',
        _kv('ACTION', delete $fields->{ACTION}),
        map { _kv($_, $fields->{$_}) }
        sort keys %$fields;

    if ($opened) {
        syslog($priority, '%s', $msg);
    }
    else {
        # Fallback: write to stderr if syslog not initialised
        warn "$ident: $msg\n";
    }
}

sub _kv {
    my ($k, $v) = @_;
    $v //= '';
    # Quote values containing spaces
    $v = qq{"$v"} if $v =~ /\s/;
    return "$k=$v";
}

sub _level {
    my ($level) = @_;
    my %levels = (
        INFO    => _LOG_INFO,
        WARNING => _LOG_WARNING,
        ERR     => _LOG_ERR,
    );
    return $levels{uc($level // 'INFO')} // _LOG_INFO;
}

1;
