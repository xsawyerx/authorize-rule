#!perl

use strict;
use warnings;

use Test::More tests => 4;
use Authorize::Rule;

my $auth = Authorize::Rule->new(
    default => -1,
    rules   => {
        cats => [ allow => '*' ]
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

