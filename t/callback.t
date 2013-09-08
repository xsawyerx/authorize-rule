#!perl

use strict;
use warnings;

use Test::More tests => 1;
ok( 1, 'Callback support is not implemented yet' );

# FIXME TODO XXX callback support check

__END__

use Test::More tests => 18;
use Authorize::Rule;

my $auth = Authorize::Rule->new(
    default => -1,
    rules   => {
        cats => [
            deny => {
                'living room' => {
                    present => [ 'John', 'Jill' ]
                }
            },

            allow => '*',
        ]
    },
);

isa_ok( $auth, 'Authorize::Rule' );
can_ok( $auth, 'check'           );

# situations:
# - john is in the house
# - only john is in the house
# - jill is in the house
# - only jill is in the house
# - both are in the house
# - none of them are in the house
# - no one is in the house

my @tests = (
    # result, room, people in the house
    [ 0, 'living room', qw<John Jeff>      ],
    [ 0, 'living room', qw<John>           ],
    [ 0, 'living room', qw<Jill Jeff>      ],
    [ 0, 'living room', qw<Jill>           ],
    [ 0, 'living room', qw<Jill John>      ],
    [ 0, 'living room', qw<Jill John Jeff> ],
    [ 1, 'living room', qw<Jeff Joan>      ], 
    [ 1, 'living room', qw<>               ],

    [ 1, 'bedroom', qw<John Jeff>      ],
    [ 1, 'bedroom', qw<John>           ],
    [ 1, 'bedroom', qw<Jill Jeff>      ],
    [ 1, 'bedroom', qw<Jill>           ],
    [ 1, 'bedroom', qw<Jill John>      ],
    [ 1, 'bedroom', qw<Jill John Jeff> ],
    [ 1, 'bedroom', qw<Jeff Joan>      ], 
    [ 1, 'bedroom', qw<>               ],
);

foreach my $test (@tests) {
    my ( $success, $resource, @in_the_house ) = @{$test};
    my $entity      = 'cats';
    my $description = "$entity " . ( $success ? 'can' : 'cannot' ) .
                      " access $resource" .
                      ( @in_the_house ?
                            " with " . join ', ', @in_the_house
                        : '' );

    my $cb = sub {
        my $prm = shift;
        grep { $_ eq $prm->{'present'} } @in_the_house;
    };

    cmp_ok(
        $auth->check( $entity => $resource, $cb ),
        '==',
        $success,
        $description,
    );
}

