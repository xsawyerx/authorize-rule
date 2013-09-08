#!perl

use strict;
use warnings;

use Test::More tests => 7;
use Authorize::Rule;

my $auth = Authorize::Rule->new(
    default => -1,
    rules   => {
        cats => [ allow => '*' ],
        dogs => [
            deny  => ['table', 'laundry room'],
            allow => '*',
        ],
    }
);

isa_ok( $auth, 'Authorize::Rule' );
can_ok( $auth, 'check'           );

cmp_ok(
    $auth->check( cats => 'kitchen' ),
    '==',
    1,
    'Cats can go in the kitchen',
);

cmp_ok(
    $auth->check( cats => 'bedroom' ),
    '==',
    1,
    'Cats can go in the bedroom',
);

cmp_ok(
    $auth->check( dogs => 'table' ),
    '==',
    0,
    'Dogs cannot go on the table',
);

cmp_ok(
    $auth->check( dogs => 'laundry room' ),
    '==',
    0,
    'Dogs cannot go on the table',
);

cmp_ok(
    $auth->check( dogs => 'bedroom' ),
    '==',
    1,
    'Dogs can go in the bedroom',
);

