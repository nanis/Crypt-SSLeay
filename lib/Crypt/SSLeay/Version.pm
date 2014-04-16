package Crypt::SSLeay::Version;
require Crypt::SSLeay;

use Exporter qw( import );

our @EXPORT = qw();

our @EXPORT_OK = qw(
    openssl_built_on
    openssl_cflags
    openssl_dir
    openssl_hex_version
    openssl_platform
    openssl_version
);

use strict;
__PACKAGE__;
__END__

=head1 NAME

Crypt::SSLeay::Version - Obtain OpenSSL version information

=head1 SYNOPSIS

    use Crypt::SSLeay::Version qw(
        openssl_cflags
        openssl_hex_version
        openssl_platform
        openssl_version
    );

    my $version = openssl_version();

    if (openssl_cflags() =~ /DOPENSSL_NO_HEARTBEATS/) {
        print "OpenSSL was compiled without heartbeats\n";
    }

=head1 SUMMARY

Exposes information provided by L<SSLeay_version|https://www.openssl.org/docs/crypto/SSLeay_version.html>.

=head1 EXPORTS

By default, the module exports nothing. You can ask for each subroutine bloew to be exported to your namespace.

=head1 SUBROUTINES

=head2 openssl_built_on

The date of the build process in the form "built on: ..." if available or ``built on: date not available'' otherwise.

=head2 openssl_cflags

The compiler flags set for the compilation process in the form "compiler: ..." if available or "compiler: information not available" otherwise.

=head2 openssl_dir

The C<OPENSSLDIR> setting of the library build in the form "OPENSSLDIR: ..." if available or "OPENSSLDIR: N/A" otherwise.

=head2 openssl_hex_version

The value of the C<OPENSSL_VERSION_NUMBER> macro as a hex string.

=head2 openssl_platform

The "Configure" target of the library build in the form "platform: ..." if available or "platform: information not available" otherwise.

=head2 openssl_version

The version of the OpenSSL library including the release date.

=head1 AUTHOR

A. Sinan Unur C<< <nanis@cpan.org> >>

=head1 COPYRIGHT

Copyright (C) 2014 A. Sinan Unur.

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it under the terms of L<Artistic License 2.0|http://www.perlfoundation.org/artistic_license_2_0>.

