#!perl

use strict;
use warnings;

use Test::More tests => 10;
use Authorize::Rule;

my $auth = Authorize::Rule->new(
    default => -1,
    rules   => {
        Bender => [
            deny  => [ 'fly ship', 'command team' ],
            allow => '*',
        ],

        Leila => [
            deny  => ['goof off'],
            allow => [ 'fly ship', 'command team' ],
        ]
    },
);

isa_ok( $auth, 'Authorize::Rule' );
can_ok( $auth, 'check'           );

my @tests = (
    [ qw< 0 Bender>, 'fly ship'     ],
    [ qw< 0 Bender>, 'command team' ],
    [ qw< 1 Bender>, 'goof off'     ],
    [ qw< 1 Bender>, 'dance around' ],
    [ qw< 1 Leila>,  'fly ship'     ],
    [ qw< 1 Leila>,  'command team' ],
    [ qw< 0 Leila>,  'goof off'     ],
    [ qw<-1 Leila>,  'dance around' ],
);

foreach my $test (@tests) {
    my ( $success, $entity, $resource ) = @{$test};
    my $description = "$entity " . ( $success ? 'can' : 'cannot' ) .
                      " $resource";

    cmp_ok(
        $auth->check( $entity => $resource ),
        '==',
        $success,
        $description,
    );
}

