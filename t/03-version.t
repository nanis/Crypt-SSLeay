#!perl

use strict;
use warnings;

use Test::More;
use Crypt::SSLeay::Version qw(
    openssl_cflags
    openssl_hex_version
    openssl_platform
    openssl_version
);

{
    my $cflags = openssl_cflags();
    ok(defined $cflags, 'openssl_cflags returns a defined value');
    like(
        $cflags,
        qr/\Acompiler:/,
        'openssl_cflags return value looks valid',
    );
}

{
    my $platform = openssl_platform();
    ok(defined $platform, 'openssl_platform returns a defined value');
    like(
        $platform,
        qr/\Aplatform:/,
        'openssl_platform return value looks valid',
    );
}

{
    my $version = openssl_version();
    ok(defined $version, 'openssl_version returns a defined value');
    like(
        $version,
        qr/\AOpenSSL/,
        'openssl_version return value looks valid',
    );
}

{
    my $hex_version = openssl_hex_version();
    ok(defined $hex_version, 'openssl_hex_version returns a defined value');
    like(
        $hex_version,
        qr/\A0x[[:xdigit:]]{8}\z/,
        'openssl_hex_version return value looks valid',
    );
}

ok(
    ! is_openssl_vulnerable_to_heartbleed(),
    'OpenSSL vulnerable to Heartbleed Bug',
);

done_testing;

# see https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
sub is_openssl_vulnerable_to_heartbleed {
    my $v = openssl_hex_version();

    return if $v lt '0x1000100f';
    return if $v ge '0x1000107f';

    return if openssl_cflags =~ m{[-/]DOPENSSL_NO_HEARTBEATS};

    my $vs = openssl_version();

    diag(<<EO_DIAG
        You have '$vs'
        and SSL Heartbeats are not disabled.

        That means your client will be vulnerable to a server
        exploiting the Heartbleed bug. The risk is compounded
        by the fact that Crypt::SSLeay does not verify hosts.
        You can still force install Crypt::SSLeay, but you
        need to be aware of this issue, and strongly consider
        upgrading to a safer version of OpenSSL.

        See also:

          - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
          - http://isc.sans.edu/diary/17945
EO_DIAG
    );
    return 1;
}
