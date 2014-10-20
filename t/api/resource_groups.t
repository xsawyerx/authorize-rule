#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 4;
use Authorize::Rule;

my $auth = Authorize::Rule->new(
    resource_groups => {
        Group => [ qw<Foo Bar Baz> ],
    },

    rules => {
        Person => {
            resource_groups => [
                [ 1, { name => 'me' } ]
            ]
        },
    },
);

my $ruleset = [ 1, { name => 'me' } ];
isa_ok( $auth, 'Authorize::Rule' );

ok(
    $auth->is_allowed( 'Person', 'Foo', { name => 'me' } ),
    'Person is allowed to Foo',
);

ok(
    $auth->is_allowed( 'Person', 'Bar', { name => 'me' } ),
    'Person is allowed to Foo',
);

ok(
    $auth->is_allowed( 'Person', 'Baz', { name => 'me' } ),
    'Person is allowed to Foo',
);

