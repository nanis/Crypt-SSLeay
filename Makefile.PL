use strict;
use warnings;

use Config;
use ExtUtils::MakeMaker;
use File::Basename qw(basename dirname);
use Getopt::Long;

eval "use ExtUtils::MakeMaker::Coverage";
$@ or print "Adding testcover target\n";

use vars qw($OPT_DEFAULT $OPT_LIBPATH $OPT_STATIC $OPT_LIVE_TESTS);

GetOptions(
    "default",     \$OPT_DEFAULT,
    "lib=s",       \$OPT_LIBPATH,
    "static",      \$OPT_STATIC,
    "live-tests!", \$OPT_LIVE_TESTS,
);

$OPT_DEFAULT ||= $ENV{CRYPT_SSLEAY_DEFAULT};

# FIND POSSIBLE SSL INSTALLATIONS

my $pkg_config = select_ssl_dir();

if ( $^O eq 'MSWin32' ) {
    fix_win32_paths( $pkg_config );
}

my @INC_FLAGS = inc_flags( $pkg_config );
my @LIB_FLAGS = lib_flags( $pkg_config );

# write include file that determines ssl support we need to include crypto.h
# for SSLeay so the version gets picked up in SSLeay.xs

write_crypt_ssleay_version_h( $pkg_config );

show_build_information( $pkg_config, \@INC_FLAGS, \@LIB_FLAGS);

my @license = do {
    my $version = $ExtUtils::MakeMaker::VERSION;
    $version =~ tr/_//d;
    $version
} > 6.3 ? (LICENSE => 'perl')
        : ();

WriteMakefile(
    NAME          => 'Crypt::SSLeay',
    AUTHOR        => 'A. Sinan Unur <nanis@cpan.org>',
    ABSTRACT_FROM => 'SSLeay.pm',
    VERSION_FROM  => 'SSLeay.pm',
    LIBS          => ["@LIB_FLAGS"],
    INC           => "@INC_FLAGS",
    NEEDS_LINKING => 1,
    PREREQ_PM     => {
        'MIME::Base64' => 0, # for Net::SSL
    },
    clean         => {
        FILES => 'crypt_ssleay_version.h test.config',
    },
    @license,
);

write_test_config($pkg_config);

## HELPERS

sub Candidate {
    my $dir = shift;
    return unless -d $dir;

    my $version_file = find_version_file($dir);
    return unless defined $version_file;

    my $fingerprint = join(':', (stat $version_file)[0,1]);

    my $inc_dir = dirname $version_file;
    return unless -e "$inc_dir/ssl.h";

    my $prefix;
    if ( 'openssl' eq lc basename $inc_dir ) {
        $prefix = 'openssl/';
        $inc_dir = dirname $inc_dir;
    }
    else {
        $prefix = '';
    }

    my ($type, $version) = get_type_and_version( $version_file );

    # Silly test to look for the library files
    my $found_lib;
    my $libd;
    my $subdir = $OPT_STATIC ? 'out32' : 'out32dll';
    if (-d "$dir/$subdir") {
        $libd = [$subdir];
    }
    elsif ($^O eq 'MSWin32' and $Config{cc} eq 'gcc') {
        # don't miss c:\strawberry\c\lib
        $libd = ['lib', 'lib/MinGW'];
    }
    else {
        # second attempt is for Solaris, like the include directory, the
        # library directory may be in a sibling directory
        $libd = ['lib', '../lib'];
    }

    SCAN:
    for my $d (@$libd) {
        my $lib_dir = "$dir/$d";
        if (opendir(LIBDIR, $lib_dir)) {
            while (defined($_ = readdir(LIBDIR))) {
                if (/\A(?:lib(?:crypto|eay32|ssl)|ssleay32)/) {
                    $found_lib = $lib_dir;
                    last SCAN;
                }
            }
            closedir(LIBDIR);
        }
    }

    if (!$found_lib) {
        my @tried = join( ',' => map {"$dir/$_"} @$libd);
        print "Did not locate expected SSL library files in @tried\n";
    }

    return {
        dir    => $dir,
        inc    => $inc_dir,
        lib    => $found_lib,
        ver    => $version,
        type   => $type,
        prefix => $prefix,
        check  => $fingerprint,
    };
}

sub parse_openssl_version {
    my ($vstr) = @_;

    # 0.9.6 or later : MNNFFPPS : major, minor, fix, patch, status (0-f)
    # 0.9.5a to before 0.9.6 : high bit of PP is set in MNNFFPPS
    # 0.9.3-dev to before 0.9.5a : MNNFFRBB : major, minor, fix, status (0-1), beta
    # prior to 0.9.3-dev, MNFP

    if ( $vstr =~ /^(?:[1-9]|0090[6-9])/ ) {
        return ( OpenSSL => parse_openssl_v096_or_later( $vstr ) );
    }
    elsif ( $vstr =~ /^00905[8-9]/ ) {
        return ( OpenSSL => parse_openssl_v095a_096( $vstr ) );
    }
    elsif ( $vstr =~ /^0090[3-5][01]/ ) {
        return ( OpenSSL => parse_openssl_v093dev_095a( $vstr ) );
    }
    else {
        return ( SSLeay => parse_openssl_pre_v093dev( $vstr ) );
    }
    return;
}

sub parse_openssl_v096_or_later {
    my ($vstr) = @_;

    # 0.9.6 or later : MNNFFPPS : major, minor, fix, patch, status (0-f)
    return unless my @v = $vstr =~ /^(.)(..)(..)(..)(.)$/;

    my ($major, $minor, $fix, $patch, $status) = map hex, @v;

    $patch = $patch ? chr( ord('a') + $patch - 1 ) : '';

    if    ( $status ==  0 ) { $status = '-dev' }
    elsif ( $status == 15 ) { $status = '' }
    else                    { $status = "-beta$status" }
    return sprintf( '%u.%u.%u%s%s', $major, $minor, $fix, $patch, $status);
}

sub parse_openssl_v095a_096 {
    my ($vstr) = @_;

    # 0.9.5a to before 0.9.6 :
    # high bit of PP is set in MNNFFPPS

    return parse_openssl_v096_or_later(
        sprintf '%08x', hex($vstr) & 0xfffff7ff
    );
}

sub parse_openssl_v093dev_095a {
    my ($vstr) = @_;

    # 0.9.3-dev to before 0.9.5a
    # MNNFFRBB : major, minor, fix, status (0-1), beta

    return unless my @v = $vstr =~ /^(0)(09)(0[3-5])([0-1])(..)$/;

    my ($major, $minor, $fix, $status, $patch) = map hex, @v;

    $patch = $patch ? chr( ord('a') + $patch - 1 ) : '';
    $status = $status ? '' : '-dev';
    return sprintf( '%u.%u.%u%s%s', $major, $minor, $fix, $patch, $status );
}

sub parse_openssl_pre_v093dev {
    my ($vstr) = @_;

    # prior to 0.9.3-dev,
    # MNFP : major, minor, fix, patch

    return unless my @v = $vstr =~ /^(0)(9)([12])([0-9])$/;

    my ($major, $minor, $fix, $patch) = map hex, @v;

    $patch = $patch ? chr( ord('a') + $patch - 1 ) : '';
    return sprintf( '%u.%u.%u%s', $major, $minor, $fix, $patch );
}

sub find_version_file {
    my $dir = shift;

    for my $file (
         "$dir/inc32/openssl/opensslv.h", # old win32 builds
         "$dir/crypto/opensslv.h", # cygwin32 builds
         "$dir/include/openssl/opensslv.h",
         "$dir/../include/openssl/opensslv.h", # Solaris
         "$dir/include/opensslv.h",
         "$dir/include/crypto.h"
    ) {
        return $file if -e $file;
    }
    return;
}

sub get_type_and_version {
    my $version_file = shift;
    my ($type, $version);

    open VERSION_FILE, $version_file or return;

    # Changed version number matching because
    # #define SSLEAY_VERSION_NUMBER   OPENSSL_VERSION_NUMBER
    # in crypto/crypto.h in at least some early versions of OpenSSL
    while (<VERSION_FILE>) {
        next unless my ($vstr) =
        /^#define\s+(?:OPENSSL|SSLEAY)_VERSION_NUMBER\s+0x([0-9A-Fa-f]+)/;

        ($type, $version) = parse_openssl_version( $vstr );
        last if defined $version;
        die "Failed to parse OpenSSL version '$vstr'" unless defined $version;
    }
    close VERSION_FILE;
    return ($type, $version);
}

sub win32_ssl_dirs {
    return (
        'c:\\openssl',
        # $Config{usrinc} points to an include directory. Use dirname
        # so the lib directory is picked up correctly
        -d $Config{usrinc} ? dirname $Config{usrinc} : (),
        # pre-Oct2009 Strawberry Perl
        $Config{prefix},
        "$Config{prefix}\\..\\c",
    );
}

sub vms_ssl_dirs {
    return (
        '/ssl$root',
    );
}

sub unix_ssl_dirs {
    return qw(
        /local
        /local/ssl
        /opt/ssl
        /usr
        /usr/local
        /usr/local/ssl
        /usr/local/openssl
    );
}

sub print_ssl_dir_not_found {
    my @possible_ssl_dirs = @_;

    print '=' x 72, "\n";
    print <<"INFO";
No installed SSL libraries found in any of the following places.
INFO
    print "    $_\n" for @possible_ssl_dirs;
    print <<"INFO";
You will have to either specify a directory location at the following
prompt, or rerun the Makefile.PL program and use the --lib switch
to specify the path. If the path in question is considered standard
on your platform, please consider filing a bug report in order to
have it taken into account in a subsequent version of Crypt::SSLeay.

INFO

    if (-f '/etc/debian_version') {
        print <<"DEBIAN_INFO";

It looks like this host is running Debian. Crypt::SSLeay needs
to be compiled with C headers provided by the libssl-dev package.
Please install that package before trying to build this module.
(You can always deinstall the package afterwards, once
Crypt::SSLeay has been built).
DEBIAN_INFO
    }
}

sub write_crypt_ssleay_version_h {
    my $pkg_config = shift;
    my $prefix = $pkg_config->{prefix};

    my @include = map { "#include<$prefix$_>" }
        qw(ssl.h crypto.h err.h rand.h pkcs12.h);

    if ($] < 5.005) {
        print "adding PL_sv_undef symbol for this ancient perl installation";
        push @include, (
            '/* defining PL_sv_undef for very old perls ($]) */',
            '#ifndef PL_sv_undef',
            '#define PL_sv_undef sv_undef',
            '#endif',
            '',
        );
    }

    my $free;
    if ( $pkg_config->{type} eq 'OpenSSL'
            and $pkg_config->{ver} !~ /\b0\.9\.[2-5]/ ) {
        $free = 'OPENSSL_free';
    }
    else {
        $free = 'free';
    }
    push @include, "#define CRYPT_SSLEAY_free $free";

    open INCLUDE, '>crypt_ssleay_version.h'
        or die "can't open crypt_ssleay_version.h for writing: $!";

    print INCLUDE map { "$_\n" } @include;

    close INCLUDE
        or die "Cannot close crypt_ssleay_version.h for output: $!\n";
}

sub possible_ssl_dirs {
    if (defined $OPT_LIBPATH) {
        # explicit from command-line
        $OPT_DEFAULT = 1;
        return ($OPT_LIBPATH);
    }
    return win32_ssl_dirs() if $^O eq 'MSWin32';
    return vms_ssl_dirs()   if $^O eq 'VMS';

    # Unix and the rest
    return unix_ssl_dirs();
}

sub candidate_ssl_dirs {
    my %seen;
    return
        grep { !$seen{$_->{check}}++ }
        map  { Candidate($_) }
        @_;
}

sub select_ssl_dir {
    my @possible_ssl_dirs = possible_ssl_dirs();
    my @candidate = candidate_ssl_dirs( @possible_ssl_dirs );
    if (@candidate == 0) {
        $OPT_DEFAULT = 0;
        print_ssl_dir_not_found( @possible_ssl_dirs );
    }

    if (@candidate == 1) {
        return $candidate[0] if $OPT_DEFAULT;
        print <<"INFO";
=======================================================
Only one $candidate[0]->{type} installation found at $candidate[0]->{dir}
Consider running 'perl Makefile.PL --default' the next
time Crypt::SSLeay is upgraded to select this directory
automatically thereby avoiding the following prompt.
=======================================================
INFO

    }
    else {
        print "Found multiple possibilities for OpenSSL\n";
        for my $c (@candidate) {
            print "  $c->{dir} ($c->{type} $c->{ver})\n";
        }
    }

    my %cand = map { $_->{dir} => { %$_ } } @candidate;
    my $ssl_dir = prompt "Which SSL install path do you want to use?",
        $candidate[0]->{dir};

    return $cand{$ssl_dir} if exists $cand{$ssl_dir};

    my $pkg_config = Candidate($ssl_dir);
    return $pkg_config if $pkg_config;

    warn <<"INFO";
$ssl_dir does not appear to be an SSL library installation, since
the required header files were not found. The build cannot proceed.
INFO
    # avoid failure reports from CPAN Testers when OpenSSL was not found
    exit 0;
}

sub inc_flags {
    return vms_inc_flags( @_ )   if $^O eq 'VMS';
    return win32_inc_flags( @_ ) if $^O eq 'MSWin32';
    return unix_inc_flags( @_ );
}

sub vms_inc_flags {
    my $pkg_config = shift;
    return ( "-I$pkg_config->{inc}" );
}

sub win32_inc_flags {
    my $pkg_config = shift;
    my $ssl_dir = $pkg_config->{dir};
    my $inc_dir = $pkg_config->{inc};

    return (
        "-I$inc_dir",
        -d "$ssl_dir/inc32" ? "-I$ssl_dir\\inc32" : (),
    );
}

sub unix_inc_flags {
    my $pkg_config = shift;

    my @flags = ("-I$pkg_config->{inc}");
    # this fix was suggested for building on RedHat 9
    push @flags, '-I/usr/kerberos/include' if -d '/usr/kerberos/include';
    return @flags;
}

sub lib_flags {
    return vms_lib_flags( @_ )   if $^O eq 'VMS';
    return win32_lib_flags( @_ ) if $^O eq 'MSWin32';
    return unix_lib_flags( @_ );
}

sub vms_lib_flags {
    my $pkg_config = shift;
    return qw(-L/SYS$SHARE -lSSL$LIBSSL_SHR32 -lSSL$LIBCRYPTO_SHR32);
}

sub win32_lib_flags {
    my $pkg_config = shift;
    my $ssl_dir = $pkg_config->{dir};

    my $mingw = $Config{cc} =~ /gcc(?:\.exe)?\z/;
    $mingw and print "Assuming MingW\n";

    my @flags;

    if ($mingw and -d "$ssl_dir\\lib\\MinGW") {
        push @flags, "-L$ssl_dir\\lib\\MinGW";
    }
    elsif(-d "$ssl_dir/lib") {
        push @flags, "-L$ssl_dir\\lib";
    }
    else {
        my $dir = $OPT_STATIC ? "$ssl_dir\\out32" : "$ssl_dir\\out32dll";
        if (-d $dir) {
            push @flags, "-L$dir";
        }
        else {
            # Allow developers to point at OpenSSL source...
            push @flags, "-L$ssl_dir";
        }
    }

    push @flags, qw(-lssleay32 -llibeay32);
    push @flags, qw(-lRSAglue -lrsaref) if $pkg_config->{type} ne 'OpenSSL';
    return @flags;
}

sub unix_lib_flags {
    my $pkg_config = shift;
    my $dir = $pkg_config->{dir};

    my @flags = (
        "-L$pkg_config->{lib}",
        qw(-lssl -lcrypto -lgcc),
        $pkg_config->{type} ne 'OpenSSL' ? qw(-lRSAglue -lrsaref) : (),
    );

     # ccc on alpha support
    if ($^O eq 'linux'
        and `uname -m` =~ /alpha/
        and !(system("nm $dir/lib/libssl.a|grep -q 'U _Ots'")>>8)
    ) {
        push @flags, '-lots';
    }

    return @flags;
}

sub write_test_config {
    my $pkg_config = shift;

    open OUT, '> test.config'
        or die "Cannot write test config: $!";

    print OUT <<"INFO";
ssl $pkg_config->{type} $pkg_config->{ver} in $pkg_config->{dir};
lib @LIB_FLAGS
inc @INC_FLAGS
cc $Config{cc}
INFO

    print OUT "network_tests ", is_live_test_wanted() ? 1 : 0, "\n";
    close OUT
        or die "Cannot write test.config: $!";
    return;
}

sub is_live_test_wanted {
    my $wanted = 'n';
    if (not defined $OPT_LIVE_TESTS) {
        print <<"INFO";
The test suite can attempt to connect to public servers
to ensure that the code is working properly. If you are
behind a strict firewall or have no network connectivity,
these tests may fail (through no fault of the code).
INFO
        $wanted = prompt "Do you want to run the live tests (y/N)?", 'N';
    }
    elsif ($OPT_LIVE_TESTS) {
        $wanted = 'y';
    }

    return $wanted =~ /\Ay(?:es)?/i;
}

sub fix_win32_paths {
    my $pkg_config = shift;

    for my $dir ($pkg_config->{dir}, $pkg_config->{inc}) {
        # external tools probably expect \ and not / for path separators
        $dir =~ tr{/}{\\};

        # default to drive C: if no drive or relative path
        unless ( $dir =~ m{\A(?:[A-Za-z]:|\.\.[\\/])} ) {
            $dir = "c:$dir";
        }
    }
    return;
}

sub show_build_information {
    my ($pkg_config, $inc_flags, $lib_flags) = @_;
    print <<"INFO";

BUILD INFORMATION
================================================
ssl library: $pkg_config->{type} $pkg_config->{ver} in $pkg_config->{dir}
ssl header:  $pkg_config->{prefix}ssl.h
libraries:   @$lib_flags
include dir: @$inc_flags
================================================
INFO
    return;
}
