package Crypt::SSLeay::MainContext;

# maintains a single instance of the Crypt::SSLeay::CTX class

use strict;
use Carp ();

require Crypt::SSLeay::CTX;

my $ctx = Crypt::SSLeay::CTX->new;
$ctx->set_cipher_list($ENV{SSL_CIPHER}) if $ENV{SSL_CIPHER};

sub main_ctx { $ctx }

my %sub_cache = ('main_ctx' => \&main_ctx );

sub import
{
    my $pkg = shift;
    my $callpkg = caller();
    my @func = @_;
    for (@func) {
        s/^&//;
        Carp::croak("Can't export $_ from $pkg") if /\W/;;
        my $sub = $sub_cache{$_};
        unless ($sub) {
            my $method = $_;
            $method =~ s/^main_ctx_//;  # optional prefix
            $sub = $sub_cache{$_} = sub { $ctx->$method(@_) };
        }
        no strict 'refs';
        *{"${callpkg}::$_"} = $sub;
    }
}

1;
