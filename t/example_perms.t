#!/usr/bin/perl
use strict;
use warnings;

use Test::More tests => 24;
use Authorize::Rule;
use Data::Dumper;

$Data::Dumper::Terse  = 1;
$Data::Dumper::Indent = 0;

# * dev:
#   - can access everything except Payroll
# * admin:
#   - can access everything
# * biz_rel:
#   - cannot access Graphs
#   - can access Invoices (but not with user parameter)
#   - can access Revenue and Payroll
#   - can access Databases only when table is Reservations
# * support:
#   - can access Databases only when table is Complaints
#   - can access Invoices
# * sysadmins:
#   - can access Graphs

my $rules = {
    dev => [
        deny  => ['Payroll'],
        allow => '*',
    ],

    admin => [ allow => '*' ],

    biz_rel => [
        deny  => ['Graphs'],
        allow => {
            Databases => { table => ['Reservations'] }
        },
        deny => { Invoices => { user => '*' } },
        allow => [ 'Invoices', 'Revenue', 'Payroll' ],
        deny => '*',
    ],

    support => [
        allow => {
            Databases => { table => ['Complaints'] },
            Invoices    => '*',
        },
        deny  => '*',
    ],

    sysadmins => [
        allow => ['Graphs'],
        deny  => '*',
    ],
};

my $auth = Authorize::Rule->new( default => -1, rules => $rules );

isa_ok( $auth, 'Authorize::Rule' );
can_ok( $auth, 'check'           );

my @groups  = keys %{$rules};
my @sources = qw<Databases Graphs Invoices Revenue Payroll>;

my @tests = (
    [ qw<1 dev       Databases> ],
    [ qw<0 dev       Payroll>   ],
    [ qw<0 biz_rel   Graphs>    ],
    [ qw<1 biz_rel   Databases>, { table => 'Reservations' } ],
    [ qw<0 biz_rel   Databases>, { table => 'else'         } ],
    [ qw<0 biz_rel   Databases> ],
    [ qw<1 biz_rel   Invoices>  ],
    [ qw<0 biz_rel   Invoices>,  { user  => 'whatever'   } ],
    [ qw<1 support   Databases>, { table => 'Complaints' } ],
    [ qw<1 support   Invoices>  ],
    [ qw<0 support   Databases>, { table => 'Reservations' } ],
    [ qw<0 support   Databases> ],
    [ qw<1 sysadmins Graphs>    ],
    [ qw<0 sysadmins Databases> ],
);

# admin accesses everything
push @tests, map { [ qw<1 admin>, $_ ] } @sources;

# biz_rel has access to everything (excluding Graphs and Databases)
push @tests, map { [ qw<1 biz_rel>, $_ ] }
             grep { $_ ne 'Graphs' && $_ ne 'Databases' } @sources;

foreach my $test (@tests) {
    my ( $success, $entity, $resource, $params ) = @{$test};

    my $description = "$entity " . ( $success ? 'can'   : 'cannot' ) .
                      " access the $resource" .
                      ( $params ? ', params: ' . Dumper($params) : '' );

    cmp_ok(
        $auth->check( $entity, $resource, $params ),
        '==',
        $success,
        $description,
    );
}

