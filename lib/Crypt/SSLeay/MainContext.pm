package Crypt::SSLeay::MainContext;

# maintains a single instance of the Crypt::SSLeay::CTX class

use strict;
use Carp ();

require Crypt::SSLeay::CTX;

# The following list is taken, with appreciation, from
# Ristic, I (2013) "OpenSSL Cookbook", Feisty Duck Ltd
# http://amzn.to/1z8rDdj
#
use constant CRYPT_SSLEAY_DEFAULT_CIPHER_LIST => join(
    q{:}, qw(
        kEECDH+ECDSA
        kEECDH
        kEDH
        HIGH
        +SHA
        +RC4
        RC4
        !aNULL
        !eNULL
        !LOW
        !3DES
        !MD5
        !EXP
        !DSS
        !PSK
        !SRP
        !kECDH
        !CAMELLIA
    )
);

my $ctx = &main_ctx();

sub main_ctx {
    my $ctx = Crypt::SSLeay::CTX->new;

    if ($ENV{CRYPT_SSLEAY_CIPHER}) {
        $ctx->set_cipher_list($ENV{CRYPT_SSLEAY_CIPHER});
    }
    else {
        $ctx->set_cipher_list(
            CRYPT_SSLEAY_DEFAULT_CIPHER_LIST
        );
    }
    $ctx;
}

my %sub_cache = ('main_ctx' => \&main_ctx );

sub import {
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
