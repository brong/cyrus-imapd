# SPDX-License-Identifier: BSD-3-Clause-CMU
# See COPYING file at the root of the distribution for more details.

package Cassandane::TestSuite::Backup;
use strict;
use warnings;
use experimental 'signatures';
use DBI;
use File::Path;
use Time::HiRes;
use Cyrus::Backup;

use base qw(Cassandane::Unit::TestSuite::Cyrus);
use Cassandane::Util::Log;

sub new ($class, @args)
{
    my $config = Cassandane::Config->default()->clone();
    $config->set(servername => 'backuptest');

    return $class->SUPER::new({
        config => $config,
    }, @args);
}

sub set_up ($self)
{
    $self->SUPER::set_up();
}

sub tear_down ($self)
{
    $self->SUPER::tear_down();
}

# Helper: set up backup directories and return ($meta, $data, $service, $servername)
sub _backup_setup ($self)
{
    my $servername = $self->{instance}->get_servername;
    my $service = $self->{instance}->get_service('backupcyrusd');

    my $data = "$self->{instance}->{basedir}/backupdata";
    my $meta = "$self->{instance}->{basedir}/backupmeta";
    mkdir($data);
    mkdir($meta);

    return ($meta, $data, $service, $servername);
}

# Helper: run BackupUser and return ($version, $size)
sub _do_backup ($self, $meta, $data, $service, $servername)
{
    return Cyrus::Backup::BackupUser(
        $service->host, $service->port,
        $meta, $data, $servername, 'cassandane',
    );
}

# Helper: open the backup state database (read-only)
sub _open_backup_db ($self, $meta)
{
    return DBI->connect(
        "dbi:SQLite:dbname=$meta/backupstate.sqlite3",
        undef, undef,
        { RaiseError => 1 },
    );
}

# Helper: does the state's indexed table still have the version 5 column?
sub _has_indexed_deleted ($self, $meta)
{
    my $dbh = $self->_open_backup_db($meta);
    my $cols = $dbh->selectall_arrayref("PRAGMA table_info(indexed)",
                                        { Slice => {} });
    $dbh->disconnect;

    return scalar grep { $_->{name} eq 'deleted' } @$cols;
}

# Helper: STAT reports whole-second mtimes, so a file rewritten in the same
# second as the last backup looks unchanged to the next one.  Call between a
# backup and a change the next backup must see.
sub _next_second ($self)
{
    my $now = time;
    Time::HiRes::sleep(0.1) while time == $now;
}

# Helper: run BackupUser, returning the protocol commands it sent
sub _do_backup_logged ($self, $meta, $data, $service, $servername)
{
    my $log = Cassandane::TestSuite::Backup::CmdLog->new;
    local $Cyrus::Backup::LOGGER_CB = sub { $log };
    $self->_do_backup($meta, $data, $service, $servername);
    return $log->{cmds};
}

# Helper: the uids named by FANNOT commands, in order
sub _fannot_uids ($self, $cmds)
{
    return [ map { my @w = split / /; @w[4..$#w] }
             grep { m/^FANNOT / } @$cmds ];
}

# Helper: send one backup protocol command, returning { $item => $content }
# for each DATA item in the response
sub _fetch_items ($self, $service, @cmd)
{
    my $io = Cyrus::Backup::GetIO($service->host, $service->port);
    my %items;
    Cyrus::Backup::iofiles($io, \@cmd, sub ($name, $fh, @) {
        seek($fh, 0, 0);
        local $/;
        $items{$name} = <$fh>;
    });
    $io->close;
    return \%items;
}

# Helper: the per-folder file names in the backup state, for all folders
sub _fmeta_names ($self, $meta)
{
    my $dbh = $self->_open_backup_db($meta);
    my $names = $dbh->selectcol_arrayref("SELECT name FROM fmeta ORDER BY name");
    $dbh->disconnect;
    return $names;
}

package Cassandane::TestSuite::Backup::CmdLog {
    sub new ($class) { bless { cmds => [] }, $class }
    sub log { }
    sub log_event { }
    sub log_debug_event { }
    sub log_debug ($self, $msg, @)
    {
        push @{$self->{cmds}}, $1 if $msg =~ m/^IOCMD: (.*)/;
    }
}

use Cassandane::Tiny::Loader;

1;
