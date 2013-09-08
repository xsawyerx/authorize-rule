#!perl

use strict;
use warnings;

use Test::More tests => 10;
use Authorize::Rule;

my $auth = Authorize::Rule->new(
    default => -1,
    rules   => {
        CEO => [
            deny  => ['Payroll'],
            allow => '*',
        ],

        support => [
            allow => [ 'UserPreferences', 'UserComplaintHistory' ],
            deny  => '*',
        ],
    }
);

isa_ok( $auth, 'Authorize::Rule' );
can_ok( $auth, 'check'           );

my @tests = (
    [ qw<0 CEO     Payroll> ],
    [ qw<1 CEO     UserPreferences> ],
    [ qw<1 CEO     UserComplaintHistory> ],
    [ qw<1 CEO     SecretStuff> ],
    [ qw<0 support Payroll> ],
    [ qw<1 support UserPreferences> ],
    [ qw<1 support UserComplaintHistory> ],
    [ qw<0 support SecretStuff> ],
);

foreach my $test (@tests) {
    my ( $success, $entity, $resource ) = @{$test};
    my $description = "$entity " . ( $success ? 'can' : 'cannot' ) .
                      " access $resource";

    cmp_ok(
        $auth->check( $entity => $resource ),
        '==',
        $success,
        $description,
    );
}

