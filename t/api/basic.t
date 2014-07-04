#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 3;
use Test::Fatal;
use Authorize::Rule;

like(
    exception { Authorize::Rule->new },
    qr/^You must provide rules/,
    'Cannot instantiate Authorize::Rule without rules',
);

my $auth = Authorize::Rule->new(
    rules => {},
);

isa_ok( $auth, 'Authorize::Rule' );
can_ok( $auth, qw<allowed is_allowed> );

