package Authorize::Rule;
# ABSTRACT: Rule-based authorization mechanism

use strict;
use warnings;
use List::Util 'first';

sub new {
    my $class = shift;
    return bless {
        rules   => [], # empty rules
        default => 0,  # deny by default
        @_
    }, $class;
}

sub default {
    my $self = shift;
    return $self->{'default'};
}

sub rules {
    my $self = shift;
    return $self->{'rules'};
}

sub check {
    my $self         = shift;
    my $entity       = shift;
    my $req_resource = shift;
    my $req_params   = shift;
    my $rules        = $self->rules;

    # deny entities that aren't in the rules
    my $perms = $rules->{$entity} or return $self->default;

    foreach ( my $i = 0; $i < $#{$perms}; $i += 2 ) {
        my $type     = $perms->[$i];
        my $resource = $perms->[ $i + 1 ];

        $type eq 'allow' || $type eq 'deny'
            or die "Type must be allow/deny (not '$type')";

        my $allowed = $type eq 'allow';

        # check full access to a resource
        # allow => '*'
        if ( !ref($resource) && $resource eq '*' ) {
            return $allowed ? 1 : 0;
        }

        # we don't allow anything other than * or refs
        my $res_ref = ref $resource
            or die 'Resource must be string (*) or HASH/ARRAY ref';

        if ( $res_ref eq 'ARRAY' ) {
            # check full access to multiple (R)esources

            # allow => [ 'R1', 'R2' ]
            # (same as: allow => { R1 => '*', R2 => '*' })
            first { $req_resource eq $_ } @{$resource}
                and return $allowed ? 1 : 0;

            # tried, move to next rule
            next;
        } elsif ( $res_ref eq 'HASH' ) {
            # check for access to a (R)esource's parameters (K)eys and (V)alues

            # find the parameters for that resource
            # if we don't have any, this is the wrong resource, try again
            my $resource_params = $resource->{$req_resource}
                or next;

            # allow => { R1 => '*' }
            if ( !ref($resource_params) && $resource_params eq '*' ) {
                return $allowed ? 1 : 0;
            }

            # we don't allow anything other than * or refs
            my $res_prm_ref = ref $resource_params
                or die 'Resource must be string(*) or HASH/ARRAY ref';

            # here we've been asked to have fine grain control over the
            # possible parameter keys and their values, but the user
            # might not have provided that information in the request
            # so we can't match this rule, we just skip
            $req_params or next;

            # we currently only allow the user to provide params in hash form
            ref $req_params and ref($req_params) eq 'HASH'
                or die 'Request params must be HASH ref';

            # allow => { R1 => [ 'K1', 'K2' ] }
            # (same as: allow => { R1 => { K1 => '*', K2 => '*' } })
            if ( $res_prm_ref eq 'ARRAY' ) {
                foreach my $res_prm ( @{$resource_params} ) {
                    first { $res_prm eq $_ } keys %{$req_params}
                        and return $allowed ? 1 : 0;
                }
            } elsif ( $res_prm_ref eq 'HASH' ) {
                foreach my $res_param ( keys %{$resource_params} ) {
                    my $res_param_val = $resource_params->{$res_param};

                    # allow => { R1 => { K1 => '*' } }
                    if ( !ref($res_param_val) && $res_param_val eq '*' ) {
                        return $allowed ? 1 : 0;
                    }

                    # allow => { R1 => { K1 => ['V1'] } }
                    # allow => { R2 => { K2 => ['V2', 'V3'] } }
                    ref $res_param_val eq 'ARRAY'
                        or die 'Resource param must be string(*) or ARRAY ref';

                    # try and find our param in the request
                    my $req_param_val = $req_params->{$res_param}
                        or next;

                    first { $req_param_val eq $_ } @{$res_param_val}
                        and return $allowed ? 1 : 0;
                }
            } else {
                die "resource parameter of type $res_prm_ref not allowed";
            }
        } else {
            die "resource of reference type $res_ref not allowed";
        }

        next; # to ignore next block
    }

    return $self->default;
}

1;

__END__

=head1 ALPHA CODE

I can't promise some of this won't change in the next few versions.

Stay tuned.

=head1 SYNOPSIS

A simple example:

    my $auth = Authorize::Rule->new(
        rules => {
            # Marge can do everything
            Marge => [ allow => '*' ],

            # Homer can do everything except go to the kitchen
            Homer => [
                deny  => ['oven'],
                allow => '*',
            ],

            # kids can clean and eat at the kitchen
            # but nothing else
            # and they can do whatever they want in their bedroom
            kids => [
                allow => {
                    kitchen => {
                        action => ['eat', 'clean'],
                    },

                    bedroom => '*',
                },

                deny => ['kitchen'],
            ],
        },
    );

    $auth->check( Marge => 'kitchen' ); # 1
    $auth->check( Marge => 'garage'  ); # 1
    $auth->check( Marge => 'bedroom' ); # 1
    $auth->check( Homer => 'oven'    ); # 0
    $auth->check( Homer => 'kitchen' ); # 1

    $auth->check( kids => 'kitchen', { action => 'eat'     } ); # 1
    $auth->check( kids => 'kitchen', { action => 'destroy' } ); # 0

=head1 DESCRIPTION

L<Authorize::Rule> allows you to provide a set of rules for authorizing access
of entities to resources.  This does not cover authentication.
While authentication asks "who are you?", authorization asks "what are you
allowed to do?"

The system is based on decisions per resources and their parameters.

The following two authorization decisions are available:

=over 4

=item * allow

Allow an action.  If something is allowed, B<1> (indicating I<true>) is
returned.

=item * deny

Deny an action.  If something is denied, B<0> (indicating I<false>) is returned.

=back

The following levels of authorization are available:

=over 4

=item * For all resources

Cats think they can do everything.

    my $rules = {
        cats => [ allow => '*' ]
    };

    my $auth = Authorize::Rule->new( rules => $rules );
    $auth->check( cats => 'kitchen' ); # 1, success
    $auth->check( cats => 'bedroom' ); # 1, success

The star (B<*>) character means 'allow/deny all resources to this entity'. By
setting the C<cats> entity to C<allow>, we basically allow cats on all
resources. The resources can be anything such as couch, counter, tables, etc.

If you don't like the example of cats (what's wrong with you?), try to think
of a department (or person) given all access to all resources in your company:

    $rules = {
        syadmins => [ allow => '*' ],
        CEO      => [ allow => '*' ],
    }

=item * Per resource

Dogs, however, provide less of a problem. Mostly if you tell them they aren't
allowed somewhere, they will comply. Dogs can't get on the table. Except the
table, we do want them to have access everywhere.

    $rules = {
        cats => [ allow => '*' ],
        dogs => [
            deny  => ['table'], # they can't go on the table
            allow => '*',       # otherwise, allow everything
        ],
    }

To provide access (allow/deny) to resources, you have specify them as an array.
This helps differ between the star character for 'all'.

Rules are read consecutively and as soon as a rule matches the matching stops.

You can provide multiple resources in a single rule. That way we can ask dogs
to also keep away from the laundry room:

    $rules = {
        cats => [ allow => '*' ],
        dogs => [
            deny  => [ 'table', 'laundry room' ], # they can't go on the table
            allow => '*',                         # otherwise, allow everything
        ],
    }

Suppose we adopted kitties and we want to keep them safe until they grow older,
we keep them in our room and keep others out:

    $rules = {
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

A corporate example might refer to some departments (or persons) having access
to some resources while denied everything else, or a certain resource not
available to some while all others are.

    $rules = {
        CEO => [
            deny  => ['Payroll'],
            allow => '*',
        ],

        support => [
            allow => [ 'UserPreferences', 'UserComplaintHistory' ],
            deny  => '*',
        ],
    }

You might ask 'what if there is no last catch-all rule at the end?' - the
answer is that the C<default> clause will be used. You can find an explanation
of it under I<ATTRIBUTES>.

=item * Per resource and per conditions

This is the most extensive control you can have. This allows you to set
permissions based on conditions, such as specific parameters per resource.

The conditions are sent to the C<check> method as additional parameters
and checked against it.

Suppose we have no problem for the dogs to walk on that one table we don't
like?

    my $rules => {
        dogs => [
            allow => {
                table => { owner => ['someone-else'] }
            },

            deny  => ['table'],
            allow => '*',
        ]
    };

    my $auth = Authorize::Rule->new( rules => $rules );
    $auth->check( dogs => 'table', { owner => 'me' } ); # 0, fails

Of course you can use a star (C<*>) as the value which means 'all'.

Since you specify values as an array, you can specify multiple values. They
will each be checked against the value of each hash key. We assume the hash
value for each key is a single string.

Here we specify a list of people whose things we don't mind the dog ruining:

    my $rules => {
        dogs => [
            allow => {
                table => { owner => ['jim', 'john'] }
            },

            deny  => ['table'],
            allow => '*',
        ]
    };

    my $auth = Authorize::Rule->new( rules => $rules );
    $auth->check( dogs => 'table', { owner => 'me'   } ); # 0, fails
    $auth->check( dogs => 'table', { owner => 'jim'  } ); # 1, succeeds
    $auth->check( dogs => 'table', { owner => 'john' } ); # 1, succeeds

=back

More complicated structures (other than hashref of keys to string values)
are currently not supported, though there are plans to add callbacks in
order to allow the user to specify their own checks of conditions.

=head1 ATTRIBUTES

=head2 default

In case there is no matching rule for the entity/resource/conditions, what
would you like to do. The default is to deny (C<0>), but you can change it
to allow by default if there is no match.

    Authorize::Rule->new(
        default => 1, # allow by default
        rules   => {...},
    );

=head2 rules

A hash reference of your permissions.

Top level keys are the entities. This can be groups, users, whichever way you
choose to view it.

    {
        ENTITY => RULES,
    }

For each entity you provide an arrayref of the rules. The will be read and
matched in sequential order. It's good practice to have an explicit last one
as the catch-all for that entity. However, take into account that there is
also the C<default>. By default it will deny unless you change the default
to allow.

    {
        ENTITY => [
            RULE1,
            RULE2,
        ],
    }

Each rule contains a key of the action, either to C<allow> or C<deny>,
followed by a resource definition.

    {
        ENTITY => [
            ACTION => RESOURCE
        ]
    }

You can provide a value of star (C<*>) to say 'this entity can do everything'
or 'this entity cannot do anyting'. You can provide an arrayref of the
resources you want to allow/deny.

    {
        Bender => [
            deny  => [ 'fly ship', 'command team' ],
            allow => '*', # allow everything else
        ],

        Leila => [
            deny  => ['goof off'],
            allow => [ 'fly ship', 'command team' ],
            # if none are matched, it will take the default
        ]
    }

You can also provide conditions as a hashref for each resource. The value
should be either a star (C<*>) to match key existence, or an arrayref to
try and match the value.

    {
        Bender => [
            allow => {
                # must have booze to function
                functioning => { booze => '*' }
            },

            # allow friendship to these people
            allow => {
                friendship => { person => [ 'Leila', 'Fry', 'Amy' ]
            },

            # deny friendship to everyone else
            deny => ['friendship'],
        ]
    }

=head1 METHODS

=head2 check

    $auth->check( ENTITY, RESOURCE );
    $auth->check( ENTITY, RESOURCE, { CONDITIONS } );

You decide what entities and resources you have according to how you define
the rules.

You can think of resources as possible actions on an interface:

    my $auth = Authorize::Rule->new(
        rules => {
            Sawyer => [ allow => [ 'view', 'edit' ] ]
        }
    );

    $auth->check( Sawyer => 'edit' )
        or die 'Sawyer is not allowed to edit';

However, if you have multiple interfaces (which you usually do in more
complicated environments), your resources are those interfaces:

    my $auth = Authorize::Rule->new(
        rules => {
            Sawyer => [ allow => [ 'Dashboard', 'Forum' ] ],
        }
    );

    # can I access the dashboard?
    $auth->check( Sawyer => 'Dashboard' );

That's better. However, it doesn't describe what Sawyer can do in each
resource. This is why you have conditions.

    my $auth = Authorize::Rule->new(
        rules => {
            Sawyer => [
                allow => {
                    Dashboard => { action => ['edit', 'view'] }
                }
            ]
        }
    );

    $auth->check( Sawyer => 'Dashboard', { action => 'delete' } )
        or die 'Stop trying to delete the Dashboard, Sawyer!';

