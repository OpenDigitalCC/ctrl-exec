package Exec::Doctor;

# The part of 'ctrl-exec-agent doctor' and 'ctrl-exec-dispatcher doctor' (T-055)
# that both share: a finding, the --fix pass, the report on stdout and the log
# line per finding. The checks themselves are in Exec::Agent::Doctor and
# Exec::Doctor::Dispatcher, which reuse the parsers and checks the programs
# already have (load_config, load_scripts, conf_dir_state, listen_plan, ...).
#
# A finding is a hashref:
#   severity  'problem' (something does not work as configured, or is unsafe)
#             or 'note' (works; worth knowing, or could not be checked)
#   check     a short stable id, e.g. 'script-ownership' (for automation)
#   what      one sentence: what was found
#   fix       the command (or edit) that fixes it; '' when there is none
#   autofix   optional coderef: the change --fix makes. Only for changes that
#             cannot lose data or widen access; returns undef when done, or the
#             reason it could not be done
#   fixed     set by apply_fixes: 1 when --fix made the change

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use JSON         qw();
use Exec::Log    qw();

# Exit status of a doctor run: 0 nothing to fix (notes may remain), 1 one or
# more problems remain, 2 doctor could not run (usage).
use constant { EXIT_OK => 0, EXIT_PROBLEMS => 1, EXIT_USAGE => 2 };

sub problem ($check, $what, $fix = '', %o) {
    return { severity => 'problem', check => $check, what => $what, fix => $fix, %o };
}

sub note ($check, $what, $fix = '', %o) {
    return { severity => 'note', check => $check, what => $what, fix => $fix, %o };
}

# Run the autofix of every finding that has one. A fix that succeeds marks the
# finding fixed; one that fails leaves it as found and says why in 'what'.
sub apply_fixes ($findings) {
    for my $f (@$findings) {
        next unless ref $f->{autofix} eq 'CODE';
        my $err = eval { $f->{autofix}->() };
        $err = ($@ || 'failed') if !defined $err && $@;
        if (defined $err) {
            $err =~ s/ at \S+ line \d+\.?\s*$//; $err =~ s/\s+\z//;
            $f->{what} .= " (--fix could not change it: $err)";
        }
        else {
            $f->{fixed} = 1;
        }
    }
    return $findings;
}

sub _counts ($findings) {
    my %n = (problem => 0, note => 0, fixed => 0);
    for my $f (@$findings) {
        if ($f->{fixed}) { $n{fixed}++ } else { $n{ $f->{severity} }++ }
    }
    return \%n;
}

sub exit_status ($findings) {
    return _counts($findings)->{problem} ? EXIT_PROBLEMS : EXIT_OK;
}

# One log line per finding (ACTION=doctor-finding), WARNING for a problem that
# remains, INFO otherwise.
sub log_findings ($program, $findings) {
    for my $f (@$findings) {
        Exec::Log::log_action(($f->{severity} eq 'problem' && !$f->{fixed}) ? 'WARNING' : 'INFO', {
            ACTION   => 'doctor-finding',
            PROGRAM  => $program,
            SEVERITY => $f->{severity},
            CHECK    => $f->{check},
            WHAT     => $f->{what},
            FIX      => (length $f->{fix} ? $f->{fix} : '-'),
            ($f->{fixed} ? (FIXED => 1) : ()),
        });
    }
}

# The JSON form: one object on one line.
#   { program, ok, problems, notes, fixed,
#     findings => [ { severity, check, what, fix, fixed }, ... ] }
# ok is true when no problem remains. A fixed finding counts as fixed, not as
# a problem or note.
sub to_json ($program, $findings) {
    my $n = _counts($findings);
    return JSON->new->canonical->encode({
        program  => $program,
        ok       => ($n->{problem} ? JSON::false : JSON::true),
        problems => $n->{problem},
        notes    => $n->{note},
        fixed    => $n->{fixed},
        findings => [ map { {
            severity => $_->{severity},
            check    => $_->{check},
            what     => $_->{what},
            fix      => $_->{fix},
            fixed    => ($_->{fixed} ? JSON::true : JSON::false),
        } } @$findings ],
    }) . "\n";
}

sub _plural ($n, $word) { return "$n $word" . ($n == 1 ? '' : 's') }

# The human form: one line per finding, problems first, then notes, then what
# --fix changed; then one summary line. With brief (the installers' form) only
# problems and fixes are listed, so a host with nothing to fix prints the
# summary line alone.
#   PROBLEM  <what> Fix: <fix>
#   note     <what> Fix: <fix>
#   fixed    <what>
sub to_text ($program, $findings, %o) {
    my $n   = _counts($findings);
    my $out = '';
    my $line = sub ($tag, $f) {
        $out .= sprintf "%-8s %s", $tag, $f->{what};
        $out .= " Fix: $f->{fix}" if length $f->{fix} && !$f->{fixed};
        $out .= "\n";
    };
    $line->('PROBLEM', $_) for grep { !$_->{fixed} && $_->{severity} eq 'problem' } @$findings;
    unless ($o{brief}) {
        $line->('note', $_) for grep { !$_->{fixed} && $_->{severity} eq 'note' } @$findings;
    }
    $line->('fixed', $_) for grep { $_->{fixed} } @$findings;

    my @parts;
    push @parts, $n->{problem} ? _plural($n->{problem}, 'problem') : 'no problems';
    push @parts, _plural($n->{note}, 'note') if $n->{note};
    push @parts, "$n->{fixed} fixed" if $n->{fixed};
    my $sum = "$program doctor: " . join(', ', @parts);
    if (!$n->{problem} && $n->{note} && $o{brief}) {
        $sum .= " (see them with: $program doctor)";
    }
    elsif (!$n->{fixed} && grep { $_->{autofix} } @$findings) {
        $sum .= " (some can be fixed with: $program doctor --fix)";
    }
    return $out . "$sum.\n";
}

# Print the report (JSON or text), log every finding, and return the exit
# status. Opts: json, brief.
sub report ($program, $findings, %o) {
    log_findings($program, $findings);
    print $o{json} ? to_json($program, $findings) : to_text($program, $findings, brief => $o{brief});
    return exit_status($findings);
}

1;
