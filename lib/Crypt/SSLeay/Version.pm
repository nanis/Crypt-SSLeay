package Crypt::SSLeay::Version;
require Crypt::SSLeay;

use Exporter qw( import );

our @EXPORT = qw();

our @EXPORT_OK = qw(
    openssl_cflags
    openssl_hex_version
    openssl_platform
    openssl_version
);

use strict;
__PACKAGE__;
__END__
