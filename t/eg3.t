#!perl

use strict;
use warnings;

use Test::More tests => 11;
use Authorize::Rule;

my $auth = Authorize::Rule->new(
    default => -1,
    rules   => {
        cats => [ deny => ['bedroom'], allow => '*' ],
        dogs => [
            deny  => [ 'table', 'laundry room', 'bedroom' ],
            allow => '*',
        ],

        kitties => [
            allow => ['bedroom'],
            deny  => '*',
        ],
    }
);

isa_ok( $auth, 'Authorize::Rule' );
can_ok( $auth, 'check'           );

my @tests = (
    [ qw<1 cats   kitchen> ],
    [ qw<0 cats   bedroom> ],
    [ qw<1 dogs   kitchen> ],
    [ qw<0 dogs   table>   ],
    [ qw<0 dogs   bedroom> ],
    [ qw<0 dogs>, 'laundry room' ],
    [ qw<0 kitties kitchen> ],
    [ qw<0 kitties table>   ],
    [ qw<1 kitties bedroom> ],
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

