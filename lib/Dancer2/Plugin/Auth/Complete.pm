use 5.008001; # XXX What version?
use strict;
use warnings;

package Dancer2::Plugin::Auth::Complete;
# ABSTRACT: Authorization module to do everything
our $VERSION = '0.001'; # VERSION

use Carp qw/croak/;
use String::CamelCase qw(camelize);
use Crypt::SaltedHash;
use Emailesque;
use Email::Valid;
use Text::Autoformat qw(autoformat break_wrap);
use Hash::Merge::Simple qw/ merge /;

use Dancer2::Plugin;
use Dancer2::Plugin::DBIC qw(schema);

my $schema = schema;
my $conf   = _merge_conf(_default_conf(), plugin_setting);

my %dispatch = (
    valid_user => \&_build_login,
);

=for Pod::Coverage extend

=head1 SYNOPSIS

  use Dancer2::Plugin::Auth::Complete;

  # Restrict access to a route
  get '/private' => needs valid_user => sub { ... };

  # Process a login request with values from a POST request
  if (login)
  {
    # A login was successful and the session is set
  }
  else {
    # Username or password was incorrect
  }

  # Logout a user
  logout if (param 'logout')

  # Functions to access user information

  my $user_details = user; # Contains details of current user

  # User not logged in
  redirect '/login' unless user;

  # Update details of user ID 6 in database
  user 6 => { firstname => "John" };

  # Delete user ID 7
  user 7 => {}

  # Check user permissions
  permission 'admin'
    or display_error "You do not have permissions to do that"

  # Send a password reset request
  reset_pw 'send' => 'email@example.com'

  # Process a password reset request
  my $code  = param 'submitted_code';
  if (my $newpw = reset_pw('do' => $code))
  {
    my $msg = "Your password has been reset to $newpw";
  }
  else {
    my $msg = "The submitted code was not valid";
  }

  # Update configuration on the fly
  Dancer2::Plugin::Auth::Complete->configure({
    emails => {
      new_account => {
        subject => "A new subject",
      },
    },
  });

  get '/login' => sub {
    # put 'return_url' in a hidden form field
    template 'login' => { return_url => params->{return_url} };
  };


=head1 DESCRIPTION

This L<Dancer2> plugin was created to be a complete "out of the box"
authentication and user management mechanism. Its aim is not to be
totally flexible, but instead to provide everything needed with
minimum coding.

It is very much at the experimental stage, and is therefore largely
untested.

At the moment it will only work with a database via DBIC, but the
aim is to merge the functionality into L<Dancer2::Plugin::Auth::Extensible>.
As such, it is likely that the module will change substantially, or indeed
cease to exist in due course.

The module needs a L<Dancer2::Plugin::DBIC> schema fully configured to
function. The schema for the authentication and users is defined in the
config file. A sensible default schema is included - see below for more
details.

=head1 QUICK START

Create the following database schema with a table called C<user>:

  | id         | int(11)      | PRI | auto_increment |
  | email      | varchar(45)  |     |                |
  | username   | varchar(45)  |     |                |
  | password   | varchar(128) |     |                |
  | pwchanged  | datetime     |     |                |
  | resetpw    | char(32)     |     |                |

Create the following config:

  Auth::Complete:
    emails:
      new_account:
        from: '"Sender" <email@example.com>'    # The sender of new account emails
      reset_pw:
        from: '"Sender" <email@example.com>'    # The sender of password resets requests

Create a HTML form with username and password fields:

  <form>
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="submit" name="submit" value="Login">
  </form>

Capture a login request:

  post '/login' => sub {
    if (param('username'))
    {
      if (login) {
        ...
      }
    }
  };

See the synopsis for further examples.

=head1 CONFIGURATION

The following configures the module. Values specified below are defaults,
unless otherwise specified.

  Auth::Complete:
    schema:
      table: user                     # The table that users are stored in
      fields:
        details: [firstname, surname] # Defaults empty. User details to retrieve from DB
        key: id                       # The database key for the table
        permissions: permissions      # The permissions field (integer, optional)
        username: username            # The username field
        email: email                  # The email field
        deleted: deleted              # A field to flag users as deleted (defaults empty - delete user instead)
        password: password            # The password field - varchar(101)
        pw_last_changed: pwchanged    # Datetime field to store time of last password change (defaults empty - optional)
        pw_reset_code: pw_reset_code  # 32 character field to store password reset requests
    permissions:
      read_only:                      # Defined permissions (defaults empty). See below.
        value: 1
        description: Read-only user
      admin:
        value: 2
        description: Administrator
    urls:
      reset_pw: /resetpw              # URL to use for password reset requests
      login: /login                   # Defines where a protected route is redirected
    emails:
      new_account:                    # Details that are sent by email when an account is created
        subject: New account details
        from: '"Sender" <email@example.com>'    # Must be defined
        plain: >
          Click the link to set your password:

          [URL]
      reset_pw:                       # Definition of email used for password reset requests
        subject: Password reset request
        from: '"Sender" <email@example.com>'    # Must be defined
        plain: >
          Click the link to reset your password:

          [URL]
    logged_in_key: user               # Defines the Dancer2 session key used for the user
    callback_key: return_url          # Defines the parameter key with the original request URL that is passed to the login route
    passthrough: user                 # A list of parameters that should be passed through to the login handler

=cut

# Private functions

# Generate a random password
sub _random_pw
{   my $foo = new String::Random;
    $foo->{'v'} = [ 'a', 'e', 'i', 'o', 'u' ];
    $foo->{'i'} = [ 'b'..'d', 'f'..'h', 'j'..'n', 'p'..'t', 'v'..'z' ];
    scalar $foo->randpattern("iviiviivi");
}

# Encrypt a password and return it
sub _encrypt_pw
{   my $password = shift;
    my $crypt = Crypt::SaltedHash->new(algorithm => 'SHA-512');
    $crypt->add($password);
    $crypt->generate;
}

# Return a random 32 char code for password resets
sub _reset_code
{
    my $gen = String::Random->new;
    $gen->{'A'} = [ 'A'..'Z', 'a'..'z' ];
    scalar $gen->randregex('\w{32}');
}

sub _email
{   
    my $args = shift;

    my $email = {
        to      => $args->{to},
        from    => $args->{from},
        subject => $args->{subject},
    };

    # Insert URLs
    $args->{plain} =~ s/\[URL\]/$args->{url}/g if $args->{url} && $args->{plain};
    $args->{html}  =~ s/\[URL\]/$args->{url}/g if $args->{url} && $args->{html};

    # YAML returns text in paragraphs without breaks between
    $args->{plain} =~ s/\n/\n\n/g if $args->{plain};

    if ($args->{plain} && $args->{html})
    {
        $email->{type} = 'multi';
        $email->{message} = {
            text => $args->{plain},
            html => $args->{html},
        };
    }
    elsif ($args->{html})
    {
        $email->{type}    = 'html';
        $email->{message} = $args->{html};
    }
    elsif ($args->{plain}) {
        $email->{type} = 'plain';
        $email->{message} = autoformat $args->{plain},
            {all => 1, break => break_wrap};
    }
    else {
        croak "No HTML or plain text message was defined";
    }

    email $email;
}

# Return or update user details.
#
# Arguments:
#   user:    (optional) a DBIC schema result set with the user in to use for this request
#   user_id: (optional) the database ID of the user. If not provided, the session user is used
#   update:  (optional) the new details to update the user with
#
# Returns the (new) user
#
sub _user
{
    my ($dsl, $args) = @_;

    my $table = camelize $conf->{schema}->{table};

    my $key_field = $conf->{schema}->{fields}->{key};
    my $permissions_field = $conf->{schema}->{fields}->{permissions};
    my $email_field    = $conf->{schema}->{fields}->{email};
    my $username_field = $conf->{schema}->{fields}->{username};

    if (my $update = $args->{update})
    {
        my $user; # Not set for new user
        my $key = $args->{user_id} ? $args->{user_id} : $update->{$key_field};
        my $deleted_field = $conf->{schema}->{fields}->{deleted};
        if ($user = $args->{user})
        {
            # Do nothing. Already have user result source
        }
        elsif ($key)
        {
            $user = $schema->resultset($table)->find($key)
                or croak "Request update ID $update->{$key_field} not found";
            croak "Requested ID $update->{$key_field} has been deleted"
                if %$update && $deleted_field && $user->$deleted_field;
        }

        if (%$update) # Empty for a delete request
        {
            my $new;
            foreach my $field (@{$conf->{schema}->{fields}->{details}})
            {
                $new->{$field} = $update->{$field} if exists $update->{$field};
            }

            # Calculate permissions value
            if ($conf->{permissions} && $update->{$permissions_field})
            {
                $new->{$permissions_field} = 0;
                foreach my $permission (keys %{$conf->{permissions}})
                {
                    $new->{$permissions_field} |= $conf->{permissions}->{$permission}->{value}
                        if $update->{$permissions_field}->{$permission};
                }
            }

            $new->{$username_field} = $update->{$username_field} if exists($update->{$username_field});
            $new->{$email_field}    = $update->{$email_field}    if exists($update->{$email_field});

            unless ($user)
            {
                # User doesn't exist. We expect a username and email.
                $new->{$username_field} or croak "Please enter a username";
                $new->{$email_field} or croak "Please enter an email address";
            }
            if (exists $new->{$email_field})
            {
                # Check for valid email, only if specified
                $new->{$email_field} = Email::Valid->address($new->{$email_field})
                    or croak "Please enter a valid email address";

                # Check it doesn't already exist
                if (!$user || $user->$email_field ne $new->{$email_field})
                {
                    my $search = { $email_field => $new->{$email_field} };
                    $search->{$deleted_field} = 0 if $deleted_field;
                    $schema->resultset($table)->search($search)->count
                        and croak "Email address already exists";
                }
            }

            my $pw_field              = $conf->{schema}->{fields}->{password};
            my $pw_last_changed_field = $conf->{schema}->{fields}->{pw_last_changed};
            if ($update->{$pw_field})
            {
                $new->{$pw_field} = _encrypt_pw $update->{$pw_field};
                $new->{$pw_last_changed_field} = \"UTC_TIMESTAMP()" if $pw_last_changed_field;
            }

            my $pw_reset_code_field = $conf->{schema}->{fields}->{pw_reset_code};
            say STDERR $pw_reset_code_field;
            $new->{$pw_reset_code_field} = $update->{$pw_reset_code_field}
                if exists $update->{$pw_reset_code_field};

            if ($user)
            {
                $user->update($new)
                    or croak "There was a database error updating the user";
            }
            else {
                # New user
                $user = $schema->resultset($table)->create($new)
                    or croak "There was a database error creating the new user";
                # Notify user
                my $code = _reset_code;
                $user->update({ $conf->{schema}->{fields}->{pw_reset_code} => $code })
                    or croak "Unable to update user table with password reset request";
                my $url           = $dsl->uri_for($conf->{urls}->{reset_pw})."/$code";
                my $email_field   = $conf->{schema}->{fields}->{email};
                my $email_details = $conf->{emails}->{new_account};
                _email {
                    to      => $user->$email_field,
                    from    => $email_details->{from},
                    subject => $email_details->{subject},
                    plain   => $email_details->{plain},
                    html    => $email_details->{html},
                    url     => $url,
                };
            }
        } else {
            # Delete user request
            $deleted_field ? $user->update({ $deleted_field => 1 }) : $user->delete
                or croak "Database error deleting user";
        }
    }

    my $user;
    if ($args->{user})
    {
        # Already have DBIC resultset for user
        $user = $args->{user};
    }
    else {
        my $user_id = $args->{user_id} || $dsl->app->session->read($conf->{logged_in_key})
            or return;
        $user = $schema->resultset($table)->find($user_id)
            or return; # User account may have been deleted since login
        my $deleted_field = $conf->{schema}->{fields}->{deleted};
        return if $deleted_field && $user->$deleted_field; # Account deleted
    }

    my $retuser;
    foreach my $field (@{$conf->{schema}->{fields}->{details}})
    {
        $retuser->{$field} = $user->$field;
    }

    $retuser->{$key_field} = $user->$key_field;
    $retuser->{$email_field} = $user->$email_field;
    $retuser->{$username_field} = $user->$username_field;

    if ($conf->{permissions})
    {
        $retuser->{$permissions_field} = {};
        my $permission_field = $conf->{schema}->{fields}->{permissions}
            or croak "Permissions field must be defined in schema when permissions are enabled";
        foreach my $permission (keys %{$conf->{permissions}})
        {
            $retuser->{$permissions_field}->{$permission} = $conf->{permissions}->{$permission} 
                if $user->$permission_field & $conf->{permissions}->{$permission}->{value};
        }
    }
    $retuser;
}

# XXX Copied from Dancer2::Plugin::Auth::Tiny - update?
sub _build_login {
    my ( $dsl, $coderef ) = @_;
    return sub {
        if ( $dsl->app->session( $conf->{logged_in_key} ) ) {
            goto $coderef;
        }
        else {
            my $data =
              { $conf->{callback_key} => $dsl->app->uri_for( $dsl->app->request->path, $dsl->app->param('query') ) };
            for my $k ( @{ $conf->{passthrough} } ) {
                $data->{$k} = $dsl->app->param($k) if $dsl->app->param($k);
            }
            return $dsl->app->redirect( $dsl->app->uri_for( $conf->{urls}->{login}, $data ) );
        }
    };
}

# See if a reset password code is in the database
sub _check_reset_code
{
    my $code = shift;

    my $table  = camelize $conf->{schema}->{table};
    my ($user) = $schema->resultset($table)->search({
        $conf->{schema}->{fields}->{pw_reset_code} => $code
    })->all;
    $user;
}

sub _default_conf
{
    {
        schema => {
            fields => {
                details       => [],
                key           => 'id',
                username      => 'username',
                email         => 'email',
                password      => 'password',
                permissions   => 'permissions',
                pw_reset_code => 'pw_reset_code',
            },
            table => 'user',
        },
        urls => {
            reset_pw => '/reset_pw',
            login    => '/login',
        },
        emails => {
            new_account => {
                subject => 'New account details',
                plain   => "Click the link to set your password:\n[URL]\n",
            },
            reset_pw => {
                subject => 'Password reset request',
                plain   => "Click the link to reset your password:\n[URL]\n",
            },
        },
        logged_in_key => 'user_id',
        callback_key  => 'return_url',
        passthrough   => [qw/user/],
    }
}

sub _merge_conf
{
    my ($original, $new) = @_;
    my $conf = merge $original, $new;

    foreach my $type ('new_account', 'reset_pw')
    {
        $conf->{emails}->{$type}->{from}
            or croak "From email address must be specified for $type emails";
    }
    $conf;
}

# Public / registered functions

=head1 FUNCTIONS

=head2 needs

C<needs> specifies a function to check for authentication before the relevant code is run (the same as L<Dancer2::Plugin::Auth::Tiny>). valid_user is provided by default, which will check that a session exists or redirect to the login page if it doesn't.

=cut

register 'needs' => sub {
    my ( $dsl, $condition, @args ) = plugin_args(@_);

    my $builder = $dispatch{$condition};

    if ( ref $builder eq 'CODE' ) {
        return $builder->( $dsl, @args );
    }
    else {
        croak "Unknown authorization condition '$condition'";
    }
};

=head2 login

C<login> attempts to login the user, using POSTed parameters. 2 parameters must be provided: username and password, which are then checked in the database according to the defined schema. Returns 1 and sets the session key if the login is successful.

=cut

register 'login' => sub {
    my ( $dsl, @args ) = plugin_args(@_);

    my $username = $dsl->app->request->param('username');
    my $password = $dsl->app->request->param('password');
    $username && $password or return;

    my $table = camelize $conf->{schema}->{table};
    my $search = {
        username => $username,
    };
    if (my $del = $conf->{schema}->{fields}->{deleted})
    {
        $search->{$del} = 0;
    }
    my ($user) = $schema->resultset($table)->search($search);

    return unless $user;
    Crypt::SaltedHash->validate($user->password, $password)
        or return;
    $dsl->app->session->write($conf->{logged_in_key} => $user->id);
    1;
};

=head2 login

C<logout> destroys the session.

=cut

register 'logout' => sub {
    my ( $dsl, @args ) = plugin_args(@_);
    $dsl->app->destroy_session;
};

=head2 user

C<user> provides various ways of accessing and updating user information. Without any arguments, it returns the details (in accordance with the schema) of the current logged-in user. If passed the ID of a user (in accordance with the key defined in the config) it returns the details of that user. The key value must be the user's key in the database (DBIC's find() is used for the lookup).

A user's details are returned using keys as defined in the schema. Permissions that a user has are returned in the same format as the configuration file (ie. a key for each permission as per the configuration file, a value as a hash containing the value and description of the permission).

If passed a user ID and a hashref of updated values, it updates the relevant user's details.

If passed an empty user ID and a hashref of values, it creates that user. If a key is provided with a database key, it updates that user instead.

If passed a user ID and an empty hashref, it deletes the user.

See the synopsis for examples.

=cut

register 'user' => sub {
    my ($dsl, $user_id, $update) = @_;
    my $args = {
        user_id => $user_id,
        update  => $update,
    };
    _user($dsl, $args);
};

=head2 permission

C<permission> checks the permissions of a particular user. Permissions are defined in the config, using binary bits for each permission, and stored in the database as an integer value.

C<permission> takes the name of a permission, checks it against the current user, and returns 1 if the user has that permission or 0 otherwise.

=cut

register 'permission' => sub {
    my ($dsl, $permission) = @_;
    my $user = _user $dsl;
    my $permissions_field = $conf->{schema}->{fields}->{permissions};
    $user->{$permissions_field}->{$permission} ? 1 : 0;
};

=head2 reset_pw

C<reset_pw> provides various ways to process password resets.

If passed the keyword 'send' followed by an email address, the email address will be sent a link to reset their password (as defined in the config). If the email address is not found, a value of 0 is returned. If the email address is found and the email is sent successfully, 1 is returned. Otherwise undef is returned.

If passed the keyword 'check' followed by a reset code, the reset code will be checked to see if it is valid. 1 will be returned for a valid code.

If passed the keyword 'do' followed by a reset code, the password for the user will be reset with an automatically generated password. The new password will be returned from the function, or nothing will be returned for an invalid code.

=cut

register 'reset_pw' => sub {
    my ($dsl, $request, @args) = @_;

    if ($request eq 'send')
    {
        # Send a password reset request to an email address
        my $username = shift @args;
        my $table    = camelize $conf->{schema}->{table};
        my ($user)   = $schema->resultset($table)->search({$conf->{schema}->{fields}->{username} => $username})->all;
        $user or return 0;

        # Generate random string for the password reset URL
        my $code = _reset_code;
        $user->update({ $conf->{schema}->{fields}->{pw_reset_code} => $code })
            or croak "Unable to update user table with password reset request";
        my $url = $dsl->uri_for($conf->{urls}->{reset_pw})."/$code";
        my $email_field = $conf->{schema}->{fields}->{email};
        my $email_details = $conf->{emails}->{reset_pw};
        _email {
            to      => $user->$email_field,
            from    => $email_details->{from},
            subject => $email_details->{subject},
            plain   => $email_details->{plain},
            html    => $email_details->{html},
            url     => $url,
        } and return 1;
        return undef;
    }
    elsif ($request eq 'check')
    {
        # Check whether a reset code is valid
        my $code = shift @args;
        _check_reset_code $code ? return 1 : return;
    }
    elsif ($request eq 'do')
    {
        # Reset a password in the database
        my ($code, $newpw) = @args;
        $newpw = _random_pw unless $newpw;
        if (my $user = _check_reset_code($code))
        {
            my $update = {
                $conf->{schema}->{fields}->{password}      => $newpw,
                $conf->{schema}->{fields}->{pw_reset_code} => undef,
            };
            _user($dsl, { user => $user, update => $update });
            $dsl->app->destroy_session;
            return $newpw;
        }
        return;
    }
    else
    {
        croak "Unknown type of request $request for reset_pw";
    }
};

=head2 configure

C<configure> provides a method to update configuration on the fly. Without any arguments it returns a hashref with the current configuration. Passed a hashref, it updates any of the defined keys and returns the new config.

=cut

sub configure
{
    my ($self, $newconf) = @_;
    $self->_merge_conf($conf, $newconf) if $newconf;
    $conf;
};


=head2 reset_pw

C<extend> provides the same functionality as L<Dancer2::Plugin::Auth::Tiny>'s extend functionality. I am unsure whether it will of any use for this module, but it is left here for the moment.

=cut

sub extend
{
    my ( $class, @args ) = @_;
    unless ( @args % 2 == 0 ) {
        croak "arguments to $class\->extend must be key/value pairs";
    }
    %dispatch = ( %dispatch, @args );
}

register_plugin for_versions => [2];

1;

=head1 PERMISSIONS

Permissions can be defined and tested for a user (see synopsis). Permissions are calculated using binary bits for each defined permission and are stored in an integer field in the database. The permissions defined in the configuration should be powers of 2.

=head1 TODO

=over 4

=item * Integrate with L<Dancer2::Plugin::Auth::Extensible>

=item * Add test suite

=item * Provide a way of overriding the auto-password generation function

=item * Store the last login time

=back

=head1 COPYRIGHT & LICENCE

Copyright 2014 Ctrl O Ltd and David Golden

This is free software, licensed under:

The Apache License, Version 2.0, January 2004

=head1 SEE ALSO

=over 4

=item * L<Dancer2::Plugin::Auth::Extensible>

=item * L<Dancer2::Plugin::DBIC>

=back

=head1 ACKNOWLEDGMENTS

This module is based on L<Dancer::Plugin::Auth::Tiny> by David Golden

=cut


# vim: ts=4 sts=4 sw=4 et:
