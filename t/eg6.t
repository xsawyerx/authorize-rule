#!perl

use strict;
use warnings;

use Test::More tests => 7;
use Authorize::Rule;
use Data::Dumper;

$Data::Dumper::Terse  = 1;
$Data::Dumper::Indent = 0;

my $auth = Authorize::Rule->new(
    default => -1,
    rules   => {
        dogs => [
            allow => {
                table => { owner => ['jim', 'john'] }
            },

            deny  => ['table'],
            allow => '*',
        ]
    },
);

isa_ok( $auth, 'Authorize::Rule' );
can_ok( $auth, 'check'           );

my @tests = (
    [ qw<1 dogs table>, { owner => 'jim'  } ],
    [ qw<1 dogs table>, { owner => 'john' } ],
    [ qw<0 dogs table>, { owner => 'me'   } ],
    [ qw<0 dogs table>   ],
    [ qw<1 dogs kitchen> ],
);

foreach my $test (@tests) {
    my ( $success, $entity, $resource, $params ) = @{$test};
    my $description = "$entity " . ( $success ? 'can' : 'cannot' ) .
                      " access $resource" .
                      ( $params ? ', ' . Dumper($params) : '' );

    cmp_ok(
        $auth->check( $entity => $resource, $params ),
        '==',
        $success,
        $description,
    );
}

