use strict;
use warnings;

use Config;
use ExtUtils::MakeMaker;
use File::Basename qw(basename dirname);
use File::Spec::Functions qw(canonpath catfile updir);
use Getopt::Long;
use OpenSSL::Versions qw(parse_openssl_version_number);

eval "use ExtUtils::MakeMaker::Coverage";
$@ or print "Adding testcover target\n";

run();

sub run {
    my %possible_ssl_dirs = (
        default => [qw(
            /usr
            /usr/local
            /usr/local/ssl
            /usr/local/openssl
            /opt/local
            /opt/local/ssl
            /opt/local/openssl
            /local
            /local/openssl
            /local/ssl
            /opt/openssl
            /opt/ssl
        )],
        haiku => [qw(
            /boot/common
            /boot/common/openssl
            /boot/common/ssl
        )],
        MSWin32 => [ map canonpath($_), (
                'c:/openssl',
                # $Config{usrinc} points to an include directory. Use dirname
                # so the lib directory is picked up correctly
                -d $Config{usrinc} ? dirname $Config{usrinc} : (),
                # pre-Oct2009 Strawberry Perl
                $Config{prefix},
                catfile($Config{prefix}, updir, 'c'),
            )
        ],
        VMS => [qw(
            /ssl$root
        )],
    );

    my ($opt_default, $opt_libpath, $opt_static, $opt_live_tests);

    GetOptions(
        "default",     \$opt_default,
        "lib=s",       \$opt_libpath,
        "static",      \$opt_static,
        "live-tests!", \$opt_live_tests,
    );

    $opt_default ||= $ENV{PERL_MM_USE_DEFAULT};
    $opt_default ||= $ENV{CRYPT_SSLEAY_DEFAULT};
    $opt_default ||= $opt_libpath;

    my @possible_ssl;
    my @candidate_ssl;

    {
        my @keys = ('default', exists $possible_ssl_dirs{$^O} ? $^O : ());
        my %seen;
        @possible_ssl = (
            $opt_libpath ||
            map @$_, @possible_ssl_dirs{@keys}
        );
        @candidate_ssl =
            grep not($seen{ $_->{fingerprint} }++),
            map check_possible_ssl_dir($_),
            @possible_ssl
        ;
    }

    unless (@candidate_ssl) {
        $opt_default = 0;
    }

    my ($selected_ssl) = $opt_default
                       ? (@candidate_ssl)
                       : prompt_select_ssl(\@possible_ssl, \@candidate_ssl)
    ;

    print selected_ssl_info_msg($selected_ssl), "\n";

    my @AUTHORS = reverse ( # reverse chronological order
        'Gisle Aas',
        'Joshua Chamas',
        'David Landgren',
        'A. Sinan Unur <nanis@cpan.org>',
    );

    my $MM_VERSION = $ExtUtils::MakeMaker::VERSION;
    $MM_VERSION =~ tr/_//d;

    my $cc = $Config{cc};
    my $incfmt = $cc eq 'cl' ? q{/I"%s"} : q{-I"%s"};
    my $libfmt = $cc eq 'cl' ? q{/libpath:"%s"} : q{-L"%s"};

    my $ssl_dir = $selected_ssl->{ssl_dir};
    my $libs = join(' ',
        sprintf($libfmt, catfile($ssl_dir, 'lib')),
        $cc eq 'cl' ? sprintf($libfmt, catfile($ssl_dir, 'out32dll')) : (),
        qw(-lz -lssl -lcrypto -lssl32 -lssleay32 -leay32)
    );

    my $inc = sprintf($incfmt, $selected_ssl->{inc_dir});
    my $crypt_ssleay_version_h = 'crypt_ssleay_version.h';
    my $test_config = 'test.config';

    WriteMakefile(
        NAME          => 'Crypt::SSLeay',
        AUTHOR        => $MM_VERSION > 6.5701 ? \@AUTHORS : $AUTHORS[0],
        ABSTRACT_FROM => 'SSLeay.pm',
        VERSION_FROM  => 'SSLeay.pm',
        LIBS          => [ $libs ],
        INC           => $inc,
        NEEDS_LINKING => 1,
        BUILD_REQUIRES => {
            'File::Basename' => 0,
            'File::Spec' => 0,
            'OpenSSL::Versions' => '0.002',
            'Try::Tiny' => '0.09',
            'Test::More' => '0.88',
        },
        PREREQ_PM     => {
            'LWP::Protocol::https' => '6.02',
            'MIME::Base64' => 0, # for Net::SSL
        },
        clean         => {
            FILES => "$crypt_ssleay_version_h $test_config",
        },
        ($MM_VERSION > 6.3 ? (LICENSE => 'artistic_2') : ()),
    );

    write_crypt_ssleay_version_h($crypt_ssleay_version_h, $selected_ssl);

    $opt_live_tests ||= is_live_test_wanted();
    write_test_config($test_config, $selected_ssl, $libs, $inc, $opt_live_tests);

    return;
}

# === HELPERS ===

sub prompt_select_ssl {
    my ($possible, $candidates) = @_;

    if (@$candidates == 0) {
        print no_ssl_lib_found_msg($possible), "\n";
    }
    elsif(@$candidates == 1) {
        print found_one_ssl_lib_msg($candidates->[0]), "\n";
    }
    else {
        print found_multiple_ssl_libs_msg($candidates), "\n";
    }

    my %cand = map { $_->{ssl_dir} => { %$_ } } @$candidates;
    my $ssl_dir = prompt(
        'Which SSL install path do you want to use?',
        $candidates->[0]{ssl_dir}
    );
    $ssl_dir =~ s/\A\s+//;
    $ssl_dir =~ s/\s+\z//;

    if ($ssl_dir) {
        return $cand{$ssl_dir} if exists $cand{$ssl_dir};

        my $info = check_possible_ssl_dir($ssl_dir);
        return $info if $info;
    }
    print no_ssl_lib_found_msg([ $ssl_dir || ()]), "\n";
    # avoid failure reports from CPAN Testers when OpenSSL was not found
    exit 0;
}

sub no_ssl_lib_found_msg {
    my ($possible) = @_;

    my $msg = <<EO_MSG;
No installed SSL libraries found.

You will have to either specify a directory location at the following
prompt, or rerun the Makefile.PL program and use the --lib switch to specify
the path. If the path in question is considered standard on your platform,
please consider filing a bug report in order to have it taken into account
in a subsequent version of Crypt::SSLeay.

EO_MSG
    if (@$possible) {
        $msg .= join("\n", 'Searched:' => map "\t$_", @$possible);
    }
    return $msg;
}

sub found_one_ssl_lib_msg {
    my ($candidate) = @_;
    return <<EO_MSG;
Only one $candidate->{ssl_type} installation found at:
    $candidate->{ssl_dir}
Consider running `perl Makefile.PL --default' the next time Crypt::SSLeay is
upgraded to select this directory automatically thereby avoiding the prompt.
EO_MSG
}

sub found_multiple_ssl_libs_msg {
    my ($candidates) = @_;
    my $msg = "Found multiple possibilities for OpenSSL\n";
    $msg .= join("\n",
        map sprintf(
            "\t%s %s in %s",
            @{$_}{qw(ssl_type version_parsed ssl_dir)}
        ),
        @$candidates
    );
    return $msg;
}

sub selected_ssl_info_msg {
    my ($ssl_info) = @_;

    my $msg = "Using the following SSL library:\n";

    for my $k (sort keys %$ssl_info) {
        $msg .= sprintf( "\t%s: %s\n", $k, $ssl_info->{$k} );
    }
    return $msg;
}

sub check_possible_ssl_dir {
    my ($dir) = @_;
    my @possible_version_files = (
        # old win32 builds
        [ inc32 => openssl => 'opensslv.h' ],
        # cygwin32 builds
        [ crypto => '' => 'opensslv.h' ],
        [ include => openssl => 'opensslv.h' ],
        # Solaris
        [ catfile(updir, 'include'), openssl => 'opensslv.h'],
        [ include => '' => 'opensslv.h' ],
        [ include => '' => 'crypto.h' ],
    );

    my $pattern =
    qr/\A#define\s+(?:OPENSSL|SSLEAY)_VERSION_NUMBER\s+0x([0-9A-Fa-f]+)/;

    VERSION_FILE:
    for my $path ( @possible_version_files ) {
        my $incfile = canonpath(catfile $dir, grep $_, @$path);
        my $incdir = canonpath(catfile $dir, $path->[0]);
        my $incpfx = $path->[1] ? "$path->[1]/" : '';
        print "Checking '$incfile'\n";

        my $version;

        if (open my $fh, '<', $incfile) {
            while (my $line = <$fh>) {
                last if ($version) = ($line =~ $pattern);
            }
            close $fh
                or print "Failed to close '$incfile': $!\n";
        }
        else {
            # print "Could not open '$incfile': $!\n";
            next VERSION_FILE;
        }

        if (defined $version) {
            # print "Found version string '$version' in '$file'\n";
        }
        else {
            print"Failed to find version string in '$incfile'\n";
            next VERSION_FILE;
        }

        my ($ssl_version, $ssl_type) = parse_openssl_version_number($version);

        return {
            fingerprint => join(':', (stat $incfile)[0,1]),
            inc_dir => $incdir,
            prefix => $incpfx,
            ssl_dir => $dir,
            ssl_type => $ssl_type,
            version_file => $incfile,
            version_parsed => $ssl_version,
            version_string => $version,
        };
    }

    return;
}

sub pathmaker {
    my ($top, $parts) = @_;

    my $incdir = canonpath(catfile $top,
        @{ $parts->{incdir} },
    );

    my $incfile = canonpath(catfile $top,
        @{ $parts->{incdir} },
        @{ $parts->{incpath} },
    );

    return ($incdir, $incfile);
}

sub write_crypt_ssleay_version_h {
    my ($include_file, $ssl_info) = @_;
    my $prefix = $ssl_info->{prefix};

    my @include = map "#include<$prefix$_>",
        qw(ssl.h crypto.h err.h rand.h pkcs12.h);

    if ($] < 5.005) {
        print "adding PL_sv_undef symbol for this ancient perl installation";
        push @include, <<EO_CHUNK;
/* defining PL_sv_undef for very old perls ($]) */
#ifndef PL_sv_undef
#define PL_sv_undef sv_undef
#endif

EO_CHUNK
    }

    my $free;
    if ($ssl_info->{ssl_type} eq 'OpenSSL'
            and $ssl_info->{version_parsed} !~ /^0[.]9[.][2-5]/ ) {
        $free = 'OPENSSL_free';
    }
    else {
        $free = 'free';
    }

    push @include, "#define CRYPT_SSLEAY_free $free";

    open my $fh, '>', $include_file
        or die "Cannot open '$include_file' for writing: $!";

    print $fh "$_\n" for @include;

    close $fh
        or die "Cannot close '$include_file': $!";
}

sub write_test_config {
    my ($config_file, $ssl_info, $libs, $inc, $live_test) = @_;

    open my $out, '>', $config_file
        or die "Cannot open '$config_file' for writing: $!";

    print $out <<EO_CHUNK;
ssl $ssl_info->{ssl_type} $ssl_info->{version_parsed} in $ssl_info->{ssl_dir}
lib $libs
inc $inc
cc $Config{cc}
network_tests $live_test
EO_CHUNK

    close $out
        or die "Cannot close '$config_file': $!";
    return;
}

sub is_live_test_wanted {
    print <<EO_CHUNK;
The test suite can attempt to connect to public servers to ensure that the
code is working properly. If you are behind a strict firewall or have no
network connectivity, these tests may fail (through no fault of the code).
EO_CHUNK
    my $wanted = prompt "Do you want to run the live tests (y/N)?", 'N';
    $wanted =~ s/\A\s+//;
    $wanted =~ s/\s+\z//;

    return $wanted =~ /\Ay(?:es)?\z/i ? 1 : 0;
}

