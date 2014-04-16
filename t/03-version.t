#!perl

use strict;
use warnings;

use Test::More;
use Crypt::SSLeay::Version qw(
    openssl_built_on
    openssl_cflags
    openssl_dir
    openssl_hex_version
    openssl_platform
    openssl_version
);

{
    my $built_on = openssl_built_on();
    ok(defined $built_on, 'openssl_built_on returns a defined value');
    note $built_on;
    like(
        $built_on,
        qr/\Abuilt on:/,
        'openssl_built_on return value looks valid',
    );
}

{
    my $cflags = openssl_cflags();
    ok(defined $cflags, 'openssl_cflags returns a defined value');
    note $cflags;
    like(
        $cflags,
        qr/\Acompiler:/,
        'openssl_cflags return value looks valid',
    );
}

{
    my $dir = openssl_dir();
    ok(defined $dir, 'openssl_dir returns a defined value');
    note $dir;
    like(
        $dir,
        qr/\AOPENSSLDIR:/,
        'openssl_dir return value looks valid',
    );
}

{
    my $platform = openssl_platform();
    ok(defined $platform, 'openssl_platform returns a defined value');
    note $platform;
    like(
        $platform,
        qr/\Aplatform:/,
        'openssl_platform return value looks valid',
    );
}

{
    my $version = openssl_version();
    ok(defined $version, 'openssl_version returns a defined value');
    note $version;
    like(
        $version,
        qr/\AOpenSSL/,
        'openssl_version return value looks valid',
    );
}

{
    my $hex_version = openssl_hex_version();
    ok(defined $hex_version, 'openssl_hex_version returns a defined value');
    note $hex_version;
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
    my %vulnerable = map $_ => undef, qw(
        0x1000100f
        0x1000101f
        0x1000102f
        0x1000103f
        0x1000104f
        0x1000105f
        0x1000106f
        0x10002001
    );

    # not one of the vulnerable versions
    return unless exists $vulnerable{ openssl_hex_version() };

    # vulnerable version, but heartbeats disabled, so immune
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
