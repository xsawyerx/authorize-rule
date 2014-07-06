package Authorize::Rule;
# ABSTRACT: Rule-based authorization mechanism

use strict;
use warnings;
use Carp       'croak';
use List::Util 'first';

sub new {
    my $class = shift;
    my %opts  = @_;

    defined $opts{'rules'}
        or croak 'You must provide rules';

    return bless {
        default => 0, # deny by default
        %opts,
    }, $class;
}

sub default {
    my $self = shift;
    @_ and croak 'default() is a ro attribute';
    return $self->{'default'};
}

sub rules {
    my $self = shift;
    @_ and croak 'rules() is a ro attribute';
    return $self->{'rules'};
}

sub is_allowed {
    my $self = shift;
    return $self->allowed(@_)->{'action'};
}

sub allowed {
    my $self         = shift;
    my $entity       = shift;
    my $req_resource = shift;
    my $req_params   = shift || {};
    my $default      = $self->default;
    my $rules        = $self->rules;
    my %result       = (
        entity   => $entity,
        resource => ($req_resource || ''),
        params   => $req_params,
    );

    # deny entities that aren't in the rules
    my $perms = $rules->{$entity}
        or return { %result, action => $default };

    # the requested and default
    my $main_ruleset = $perms->{$req_resource} || [];
    my $def_ruleset  = $perms->{''}            || [];

    # if neither, return default action
    @{ $main_ruleset } || @{ $def_ruleset }
        or return { %result, action => $default };

    foreach my $rulesets ( $main_ruleset, $def_ruleset ) {
        my $ruleset_idx;
        my $label;

        foreach my $ruleset ( @{$rulesets} ) {
            if ( ! ref $ruleset ) {
                $label = $ruleset;
                next;
            }

            $ruleset_idx++;

            my $action = $self->match_ruleset( $ruleset, $req_params );
            defined $action
                and return {
                    %result,
                    action      => $action,
                    ruleset_idx => $ruleset_idx,
                  ( label       => $label        )x!! defined $label,
                };

            undef $label;
        }
    }

    return { %result, action => $default };
}

sub match_ruleset {
    my $self       = shift;
    my $ruleset    = shift;
    my $req_params = shift;

    my ( $action, @rules ) = @{$ruleset}
        or return;

    foreach my $rule (@rules) {
        if ( ref $rule eq 'HASH' ) {
            # check defined params by rule against requested params
            foreach my $key ( keys %{$rule} ) {
                defined $req_params->{$key}
                    or return; # no match

                $req_params->{$key} eq $rule->{$key}
                    or return; # no match
            }
        } elsif ( ! ref $rule ) {
            defined $req_params->{$rule}
                or return; # no match
        } else {
            croak 'Unknown rule type';
        }
    }

    return $action;
}

1;

__END__

=head1 ALPHA CODE

I can't promise some of this won't change in the next few versions.

Stay tuned.

=head1 SYNOPSIS

This is an extensive example, showing various options:

    my $auth = Authorize::Rule->new(
        rules => {
            dev => {
                Payroll => [ [0] ], # always deny
                ''      => [ [1] ], # default allow for unknown resources
            },

            tester => {
                '' => [
                    # labeled rulesets
                    'check tester' => [
                        # all rules must apply
                        # key 'is_test' with value 1
                        # and keys test_name/test_id must exist
                        1, { is_test => 1 }, 'test_name', 'test_id'
                    ],
                    'default' => [0],
                ]
            },

            admin => { '' => [ [1] ] },

            biz_rel => {
                Graphs    => [ [0] ],
                Databases => [
                    # access to reservations table
                    [ 1, { table => 'Reservations' } ],
                ],

                Invoices => [
                    [ 0, 'user' ],
                    [ 1         ],
                ],

                Payroll => [ [1] ],
                Revenue => [ [1] ],
                ''      => [ [0] ],
            },

            support => {
                Databases => [
                    [ 1, { table => 'Complaints' } ],
                ],

                Invoices => [ [1] ],
                ''       => [ [0] ],
            },

            sysadmins => {
                Graphs => [ [1] ],
                ''     => [ [0] ],
            },
        },
    );

I<(this example is not taken from any actual code)>

=head1 DESCRIPTION

L<Authorize::Rule> allows you to provide a set of rulesets, each containing
rules, for authorizing access of entities to resources. This does not cover
authentication, or fine-grained parameter checking.

While authentication asks "who are you?", authorization asks "what are you
allowed to do?"

The system is based on decisions per entities, resources, and any optional
parameters.

=head1 SPECIFICATION

The specification covers several elements:

=over 4

=item * Entity

=item * Resource

=item * Action

=item * Optional parameters

=item * Optional label

=back

The general structure is:

    {
        ENTITY => {
            RESOURCE => [
                OPTIONAL_LABEL => [ ACTION, RULE1, RULE2, ...RULE10 ],
            ]
        }

    }

Allowed rules are:

    # parameters must have this key with this value
    [ $action, { key => 'value' } ]
    [ $action, { name => 'Marge' } ]
    [ $action, { names => [ qw<Marge Homer Lisa Bart Maggie> ] } ]
    [ $action, { families => { Simpsons => [...] } } ]

    # parameters must have these keys, values aren't checked
    [ $action, 'key1', 'key2', ... ]

    # they can be seamlessly mixed
    [ $action, { Company => 'Samsung' }, { Product => 'Phone' }, 'model_id' ]

    # and yes, this is the equivalent of:
    [ $action, { Company => 'Samsung', Product => 'Phone' }, 'model_id' ]

    # labels can be applied to rulesets:
    'verifying test account' => [ $action, { username => 'tester' } ]

An action is either true or false, but can be provided any defined value.
Traditionally these will be C<1> or C<0>:

    [ 1, RULES... ]
    [ 0, RULES... ]
    [ 'FAILURE', RULES... ]

    my $result = $auth->is_allowed( $entity, $resource );
    if ( $result eq 'FAILURE' ) {
        ...
    }

Rules are read consecutively and as soon as a rule matches the matching stops.

=head1 EXAMPLES

=head2 All resources

Cats think they can do everything, and they can:

    my $rules = {
        Cat => {
            # default rule for any unmatched resource
            '' => [
                # only 1 ruleset with no actual rules, just an action
                [1]
            ],
        }
    }

    my $auth = Authorize::Rule->new( rules => $rules );
    $auth->check( cats => 'kitchen' ); # 1, success
    $auth->check( cats => 'bedroom' ); # 1, success

If you don't like the example of cats (what's wrong with you?), try to think
of a department (or person) given all access to all resources in your company:

    $rules = {
        Sysadmins => {
            '' => [ [1] ],
        },

        CEO => {
            '' => [ [1] ],
        },
    }

=head2 Per resource

Dogs, however, provide less of a problem. Mostly if you tell them they aren't
allowed somewhere, they will comply. Dogs can't get on the table. Other than
the table, we do want them to have access everywhere.

    $rules = {
        Cat => {
            '' => [ [1] ],
        },

        Dog => {
            Table => [ [0] ], # can't go on the table
            ''    => [ [1] ], # otherwise, allow everything
        },
    }

A corporate example might refer to some departments (or persons) having access
to some resources while denied everything else, or a certain resource not
available to some while all others are.

    $rules = {
        CEO => {
            Payrolls => [ [0] ], # no access to Payrolls
            ''       => [ [1] ], # access to everything else
        },

        Support => {
            UserPreferences      => [ [1] ], # has access to this
            UserComplaintHistory => [ [1] ], # and this
            ''                   => [ [0] ], # but that's it
        },
    }

=head2 Per resource and per conditions

This is the most extensive control you can have. This allows you to set
permissions based on conditions, such as specific parameters per resource.

Suppose we have no problem for the dogs to walk on that one table we don't
like?

    my $rules => {
        Dog => {
            Table => [
                # if the table is owned by someone else, it's okay
                [ 1, { owner => 'someone-else' } ],

                # otherwise, no
                [0],
            ],

            '' => [ [1] ], # but generally dogs can go everywhere
        }
    };

    my $auth = Authorize::Rule->new( rules => $rules );
    $auth->is_allowed( Dog => 'Table', { owner => 'me' } ); # 0, fails

You can also specify just the existence (and C<define>ss) of keys:

    my $rules = {
        Support => {
            ClientTable => [
                [ 1, 'user_id' ], # must have a user id to access the table
                [0],              # otherwise, access denied
            ]
        }
    };

=head2 OR conditions

If you want to create an B<OR> condition, all you need is to provide another
ruleset:

    my $rules = {
        Dog => {
            Table => [
                [ 1, { carer => 'Jim'  } ], # if Jim takes care of the dog
                [ 1, { carer => 'John' } ], # or if John does
                [0],                        # otherwise, no
            ]
        }
    };

    $auth->is_allowed( Dog => 'Table', { owner => 'me'   } ); # 0, fails
    $auth->is_allowed( Dog => 'Table', { owner => 'Jim'  } ); # 1, succeeds
    $auth->is_allowed( Dog => 'Table', { owner => 'John' } ); # 1, succeeds

=head2 AND conditions

If you want to create an B<AND> condition, just add more rules to the
ruleset:

    my $rules = {
        Dog => {
            Table => [
                [
                    1,                     # allow if...
                    { carer => 'John'   }, # john is the carer
                    { day   => 'Sunday' }, # it's Sunday
                    { clean => 1        }, # you're clean
                    'tag_id',              # and you have a tag id
                # otherwise, no
                [0],
            ]
        }
    };

As shown in other examples above, any hash rules can be put in the same
hash, so this is equivalent:


    my $rules = {
        Dog => {
            Table => [
                [
                    1,                     # allow if...
                    {
                        carer => 'John',   # john is the carer
                        day   => 'Sunday', # it's Sunday
                        clean => 1,        # you're clean
                    },
                    'tag_id',              # and you have a tag id
                # otherwise, no
                [0],
            ]
        }
    };

The order of rules does not change anything, except how quickly it might
mismatch. If you have insane amounts of rules and conditions, it could make
a difference, but unlikely.

=head2 labeling

Optional labels can be applied in order to help structure rulesets and
understand which ruleset matched.

    my $rules = {
        Tester => {
            # Tester's rulesets for any resource
            '' => [
                # regular ruleset
                [ 1, 'test_mode' ], # if we're in test_mode

                # labeled ruleset
                'has test ID' => [ 1, 'test_id' ], # has a test ID
            ],
        },
    };

Labeled and unlabeled rulesets can be interchanged freely.

=head2 Catch all

You might ask I<what if there is no last rule at the end for any other
resource?>

The answer is simple: the C<default> clause will be used. You can find an
explanation of it under I<ATTRIBUTES>.

=head2 Callbacks

Currently callbacks are not supported, but there are plans for a later
version. The issue with callbacks is that you will not be able to serialize
the rules.

=head1 ATTRIBUTES

=head2 default

In case there is no matching rule for the entity/resource/conditions, what
would you like to do. The default is to deny (C<0>), but you can change it
to allow by default if there is no match.

    Authorize::Rule->new(
        default => 1, # allow by default
        rules   => {...},
    );

    Authorize::Rule->new(
        default => -1, # to make sure it's the catch-all
        rules   => {...},
    );

=head2 rules

A hash reference of your permissions, defined by the specification explained
above.

=head1 METHODS

=head2 is_allowed

Returns the action for the entity and resource.

Effectively, this is the C<action> key in the result coming from the
C<allowed> method described below.

=head2 allowed

    my $result = $auth->allowed( $entity, $resource, $params );

Returns an entire hash containing every piece of information that might be
helpful:

=over 4

=item * entity

=item * resource

=item * params

=item * action

=item * label

=item * ruleset_idx

The index of the ruleset, starting from 1.

=back

