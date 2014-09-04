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
use DateTime;

use Dancer2::Plugin;
use Dancer2::Plugin::DBIC qw//;

my $schema = Dancer2::Plugin::DBIC::schema;
my $conf   = _merge_conf(_default_conf(), plugin_setting);
my $user_callback;

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
  user 'update', id => 6, firstname => "John";

  # Delete user ID 7
  user 'delete', id => 7;

  # Check user permissions
  permission 'admin'
    or display_error "You do not have permissions to do that"

  # Send a password reset request
  reset_pw 'send' => 'email@example.com'

  # Process a password reset request
  my $code  = param 'submitted_code';
  if (my $newpw = reset_pw('code' => $code))
  {
    my $msg = "Your password has been reset to $newpw";
  }
  else {
    my $msg = "The submitted code was not valid";
  }

  # Generate a new password when given existing password
  my $new_pw = reset_pw 'password' => 'mysecret';

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

sub _usertable_rs
{
    my $table = camelize $conf->{schema}->{table};
    $schema->resultset($table);
}

sub _user_get
{
    my ($dsl, %params) = @_;
    my %fields     = %{$conf->{schema}->{fields}};
    my $search = \%params;
    my $deleted_field = $fields{deleted};
    $search->{$deleted_field} = 0
        if $fields{deleted} && !exists $search->{$deleted_field};
    my $request_field = $fields{request};
    $search->{$request_field} = 0
        if $fields{request} && !exists $search->{$request_field};
    _user($dsl, search => $search);
}

sub _user_update
{
    my $dsl        = shift;
    my %args       = @_;
    my $update     = $args{update};
    my $user       = $args{user};
    my %fields     = %{$conf->{schema}->{fields}};

    if ($user = $args{user})
    {
        # Do nothing. Already have user result source
    }
    elsif (my $key = $update->{$fields{key}})
    {
        # Existing user specified - update
        $user = _usertable_rs->find($key)
            or croak "Request update ID $key not found";
    }

    my $new;
    foreach my $field (@{$fields{details}})
    {
        $new->{$field} = $update->{$field} if exists $update->{$field};
    }

    # Calculate permissions value
    if ($conf->{permissions} && $update->{$fields{permissions}})
    {
        $new->{$fields{permissions}} = 0;
        foreach my $permission (keys %{$conf->{permissions}})
        {
            $new->{$fields{permissions}} |= $conf->{permissions}->{$permission}->{value}
                if $update->{$fields{permissions}}->{$permission};
        }
    }

    my $email_field = $fields{email};
    $new->{$fields{username}} = $update->{$fields{username}}
        if exists($update->{$fields{username}});
    $new->{$email_field}      = $update->{$email_field}
        if exists($update->{$email_field});
    $new->{$fields{request}}  = $update->{$fields{request}}
        if exists($update->{$fields{request}});
    $new->{$fields{deleted}}  = $update->{$fields{deleted}}
        if exists($update->{$fields{deleted}});

    unless ($user)
    {
        # User doesn't exist. We expect a username and email.
        $new->{$fields{username}}
            or croak "Please enter a username";
        $new->{$email_field}
            or croak "Please enter an email address";
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
            my $deleted_field = $conf->{schema}->{fields}->{deleted};
            $search->{$deleted_field} = 0 if $deleted_field;
            my $request_field = $conf->{schema}->{fields}->{request};
            $search->{$request_field} = 0 if $request_field;
            _usertable_rs->search($search)->count
                and croak "Email address already exists";
        }
    }

    my $pw_last_changed_field = $conf->{schema}->{fields}->{pw_last_changed};
    if ($update->{$fields{password}})
    {
        $new->{$fields{password}}        = _encrypt_pw $update->{$fields{password}};
        $new->{$fields{pw_last_changed}} = DateTime->now
            if $fields{pw_last_changed};
    }

    $new->{$fields{pw_reset_code}} = $update->{$fields{pw_reset_code}}
        if exists $update->{$fields{pw_reset_code}};

    if ($user)
    {
        $user->update($new)
            or croak "There was a database error updating the user";
    }
    else {
        # New user
        $user = _usertable_rs->create($new)
            or croak "There was a database error creating the new user";

        # Notify user if not an account request
        unless ($update->{$fields{request}})
        {
            my $code = _reset_code;
            $user->update({ $conf->{schema}->{fields}->{pw_reset_code} => $code })
                or croak "Unable to update user table with password reset request";
            my $url           = $dsl->uri_for($conf->{urls}->{reset_pw})."/$code";
            my $email_field   = $fields{email};
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
    }
    _user($dsl, user => $user);
}

sub _user
{
    my ($dsl, %args) = @_;

    my %fields = %{$conf->{schema}->{fields}};

    my @users;
    if ($args{user})
    {
        # Already have DBIC resultset for user
        @users = ($args{user});
    }
    else {
        my $search  = $args{search};
        @users = _usertable_rs->search($search)->all;
        return unless @users;
    }

    my @retusers;
    foreach my $user (@users)
    {
        my $retuser;

        foreach my $field (@{$conf->{schema}->{fields}->{details}})
        {
            $retuser->{$field} = $user->$field;
        }

        foreach my $field (qw/key email username password/)
        {
            my $col = $fields{$field};
            $retuser->{$col} = $user->$col;
        }

        if ($conf->{permissions})
        {
            $retuser->{$fields{permissions}} = {};
            my $permission_field = $fields{permissions}
                or croak "Permissions field must be defined in schema when permissions are enabled";
            foreach my $permission (keys %{$conf->{permissions}})
            {
                my $user_perm = $user->$permission_field ? int $user->$permission_field : 0;
                $retuser->{$permission_field}->{$permission} = $conf->{permissions}->{$permission} 
                    if $user_perm & $conf->{permissions}->{$permission}->{value};
            }
        }

        if ($user_callback)
        {
            $retuser = &$user_callback($retuser, $user);
        }
        push @retusers, $retuser;
        last unless wantarray;
    }

    wantarray ? @retusers : pop @retusers;
}

sub _user_logged_in
{
    my $dsl     = shift;
    my %fields  = %{$conf->{schema}->{fields}};
    my $user_id = $dsl->app->session->read($conf->{logged_in_key})
        or return;
    my $search  = { $fields{key} => $user_id };
    return _user $dsl, search => $search;
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

    my ($user) = _usertable_rs->search({
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

    my $user  = _user_get($dsl, $conf->{schema}->{fields}->{username} => $username);

    return unless $user;
    Crypt::SaltedHash->validate($user->{password}, $password)
        or return;
    my $keyf = $conf->{schema}->{fields}->{key};
    $dsl->app->session->write($conf->{logged_in_key} => $user->{$keyf});
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

C<user> provides various ways of accessing and updating user information. Without any arguments, it returns the details (in accordance with the schema) of the current logged-in user. Other functions can be added using a keyword follwed by parameters:

C<user 'get' => %search> is used to search for a user. It should be passed a hash with details of the user(s) to search for. In scalar context returns the first (or only) user; in list context returns all matching users.

A user's details are returned using keys as defined in the schema. Permissions that a user has are returned as a hash, with a key for each permission present. Each key has a value of a hash that contains details of the permission (as per the config file). See the permissions section for further information.

C<user 'update' => %details> is used to update or create a user. It should be passed a hash with the details to update. If the hash contains the schema's key, then that user will be updated, but if no key is passed then a new user is created. Either way, a hash of the updated or created user is returned.

C<user 'delete' => %search> is used in the same manner as C<get>, except that all resultant users are deleted. Note that users are actually deleted from the database, even if the deleted option is used in the configuration. To only flag users as deleted, use C<update> instead.

See the synopsis for examples.

=cut

register 'user' => sub {
    my ($dsl, $action, %params) = @_;

    my %fields = %{$conf->{schema}->{fields}};

    if (!$action)
    {
        return _user_logged_in $dsl;
    }
    elsif ($action eq 'update')
    {
        return _user_update $dsl, update => \%params;
    }
    elsif ($action eq 'delete')
    {
        return _usertable_rs->search(\%params)->delete
            or croak "Database error when deleting user";
    }
    elsif ($action eq 'get')
    {
        return _user_get $dsl, %params;
    }
    else {
        croak "Unknown action $action";
    }
};

=head2 permission

C<permission> checks the permissions of a particular user. Permissions are defined in the config, using binary bits for each permission, and stored in the database as an integer value.

C<permission> takes the name of a permission, checks it against the current user, and returns 1 if the user has that permission or 0 otherwise.

=cut

register 'permission' => sub {
    my ($dsl, $permission) = @_;
    my $user = _user_logged_in $dsl;
    my $permissions_field = $conf->{schema}->{fields}->{permissions};
    $user->{$permissions_field}->{$permission} ? 1 : 0;
};

=head2 reset_pw

C<reset_pw> provides various ways to process password resets.

If passed the keyword 'send' followed by an email address, the email address will be sent a link to reset their password (as defined in the config). If the email address is not found, a value of 0 is returned. If the email address is found and the email is sent successfully, 1 is returned. Otherwise undef is returned.

If passed the keyword 'check' followed by a reset code, the reset code will be checked to see if it is valid. 1 will be returned for a valid code.

If passed the keyword 'code' followed by a reset code, the password for the user will be reset with an automatically generated password. The new password will be returned from the function, or nothing will be returned for an invalid code. An optional additional parameter can be passed, which will be the new password, in which case that will be used instead of an automatically generated password.

If passed the keyword 'password' followed by the existing password for the user, then as long as the password is correct, a new password will be generated and returned. If an optional additional parameter is provided, that will be used for the new password, rather than an automatically generated password.

=cut

register 'reset_pw' => sub {
    my ($dsl, $request, @args) = @_;

    if ($request eq 'send')
    {
        # Send a password reset request to an email address
        my $email = shift @args;
        my $user  = _user_get($dsl, $conf->{schema}->{fields}->{email} => $email);
        $user or return 1; # Return success on user not found for security reasons

        # Generate random string for the password reset URL
        my $code = _reset_code;
        my $keyf = $conf->{schema}->{fields}->{key};
        _user_update(
            $dsl,
            update => {
                $keyf => $user->{$keyf},
                $conf->{schema}->{fields}->{pw_reset_code} => $code
            }
        );
        my $url = $dsl->uri_for($conf->{urls}->{reset_pw})."/$code";
        my $email_field = $conf->{schema}->{fields}->{email};
        my $email_details = $conf->{emails}->{reset_pw};
        _email {
            to      => $user->{$email_field},
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
    elsif ($request eq 'code')
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
            _user_update($dsl, user => $user, update => $update);
            $dsl->app->destroy_session;
            return $newpw;
        }
        return;
    }
    elsif ($request eq 'password')
    {
        # Reset a password in the database
        my ($password, $newpw) = @args;
        my $user   = _user $dsl;
        my %fields = %{$conf->{schema}->{fields}};
        my $dbpw = $user->{$fields{password}};
        Crypt::SaltedHash->validate($dbpw, $password)
            or return;
        $newpw = _random_pw unless $newpw;
        my $update = {
            $fields{id}       => $user->{$fields{id}},
            $fields{password} => $newpw,
        };
        _user($dsl, update => $update);
        return $newpw;
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


=head2 extend

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

=head2 user_callback

C<user_callback> allows a subroutine to be specified that will be executed each time a user is retrieved from the database. This allows additional parameters to be saved into the user hash before it is returned to the calling program. C<user_callback> should be passed a code reference which should return the updated hashref. The relevant coderef will be called with 2 parameters: the initial user hashref (to be altered) and a resultset containing the user retrieved from the database. For example:

  Dancer2::Plugin::Auth::Complete->user_callback( sub {
    my ($retuser, $user) = @_;
    $retuser->{child} = $user->age < 18 ? 1 : 0;
    $retuser;
  });

=cut

sub user_callback
{
    my ($self, $cb) = @_;
    $user_callback = $cb;
    $cb;
}

register_plugin for_versions => [2];

1;

=head1 PERMISSIONS

Permissions can be defined and tested for a user (see synopsis). Permissions are calculated using binary bits for each defined permission and are stored in an integer field in the database. The permissions defined in the configuration should be powers of 2.

When fetching user details, the permissions field as defined in the config is converted to a hashref, with a key aligning to each permission that a user has. The value of each key will be set to a hash containing details of the particular permission. Permissions that a user does not have will not exist. When updating a user, a hashref should also be provided, but with a key with a true value for each permission that a user should be set to.

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
