use 5.006;
use strict;
use warnings;

use Devel::CheckLib;
use ExtUtils::CBuilder;
use ExtUtils::MakeMaker;
use Getopt::Long qw( GetOptionsFromArray );
use IO::Interactive::Tiny;
use Path::Class;
use Try::Tiny;

run(\@ARGV) unless caller;

sub run {
    my $argv = shift;

    eval "use ExtUtils::MakeMaker::Coverage";
    $@ or print "Adding testcover target\n";

    my @authors = reverse ( # reverse chronological order
        'Gisle Aas',
        'Joshua Chamas',
        'David Landgren',
        'A. Sinan Unur <nanis@cpan.org>',
    );

    my $mm_version = $ExtUtils::MakeMaker::VERSION;
    $mm_version =~ tr/_//d;

    my %opt;
    GetOptionsFromArray(
        $argv,
        \%opt,
        'incpath=s',
        'libpath=s',
        'live-tests!',
        'static',
    ) or die "Error parsing command line options\n";

    if (
        (not exists $opt{incpath}) and
        (exists $ENV{OPENSSL_INCLUDE})
    )
    {
        $opt{incpath} = $ENV{OPENSSL_INCLUDE};
    }

    if (
        (not exists $opt{libpath}) and
        (exists $ENV{OPENSSL_LIB})
    )
    {
        $opt{libpath} = $ENV{OPENSSL_LIB};
    }

    # Address RT #78848 and RT #88269

    for my $path (grep defined, @opt{qw(incpath libpath)}) {
        try {
            $path = file($path)->absolute->resolve
        }
        catch {
            die "Error resolving '$path': $_";
        };
    }

    check_lib_or_exit(
        debug => 0,
        lib => 'ssl',
        header => 'openssl/ssl.h',
        $opt{libpath} ? (libpath => "$opt{libpath}") : (),
        $opt{incpath} ? (incpath => "$opt{incpath}") : (),
    );

    my $my_openssl_version_cmd = eval {
        build_openssl_version('openssl-version.c', \%opt);
    };

    unless (defined $my_openssl_version_cmd) {
        print "Failed to build and link a simple executable using OpenSSL:\n";
        exit 0;
    };

    show_cmd_output($my_openssl_version_cmd);

    # Only check other locations if command line option was not specified
    if (
        (not exists $opt{'live-tests'}) and
        (exists $ENV{CRYPT_SSLEAY_LIVE_TEST_WANTED})
    )
    {
        $opt{live_tests} = $ENV{CRYPT_SSLEAY_LIVE_TEST_WANTED};
    }

    if (
        (not exists $opt{'live-tests'}) and
        (IO::Interactive::Tiny::is_interactive())
    )
    {
        $opt{'live-tests'} = is_live_test_wanted();
    }

    my %params = (
        META_MERGE => {
            resources => {
                repository => 'https://github.com/nanis/Crypt-SSLeay',
            },
        },

        NAME => 'Crypt::SSLeay',

        AUTHOR => \@authors,

        ABSTRACT_FROM => 'SSLeay.pm',

        VERSION_FROM => 'SSLeay.pm',

        INC => $opt{incpath} ? qq{-I$opt{incpath}} : q{},

        LIBS => $opt{libpath}
                ? [ qq{-L$opt{libpath} -lssl -lcrypto -lssl32 -lssleay32 -leay32 -lz} ]
                : [  q{-lssl -lcrypto -lssl32 -lssleay32 -leay32 -lz} ]
        ,

        ($opt{static} ? (LINK_TYPE => 'static') : ()),

        TEST_REQUIRES => {
            'Try::Tiny' => '0.09',
            'Test::More' => '0.19',
        },

        CONFIGURE_REQUIRES => {
            'Devel::CheckLib' => '0.99',
            'ExtUtils::CBuilder' => '0.280205',
            'Getopt::Long' => 0,
            'IO::Intereactive::Tiny' => 0,
            'Path::Class' => '0.26',
        },

        PREREQ_PM => {
            'LWP::Protocol::https' => '6.02',
            'MIME::Base64' => 0, # for Net::SSL
        },

        clean => {
            FILES => "test.config openssl-version.o $my_openssl_version_cmd",
        },

        LICENSE => 'artistic_2',

        MIN_PERL_VERSION => 5.006,
    );

    $mm_version = eval $mm_version;

    die "EXTRA_META is deprecated" if exists $params{EXTRA_META};
    die "License not specified" if not exists $params{LICENSE};

    if (
        $params{AUTHOR} and
        ref($params{AUTHOR}) eq ref([]) and
        $mm_version < 6.5705
    ) {
        $params{META_ADD}->{author} = $params{AUTHOR};
        $params{AUTHOR}=join(', ', @{$params{AUTHOR}});
    }

    if ($params{TEST_REQUIRES} and $mm_version < 6.64) {
        $params{BUILD_REQUIRES} = {
            %{ $params{BUILD_REQUIRES} || {} },
            %{ $params{TEST_REQUIRES} },
        };
        delete $params{TEST_REQUIRES};
    }

    if ($params{BUILD_REQUIRES} and $mm_version < 6.5503) {
        #EUMM 6.5502 has problems with BUILD_REQUIRES
        $params{PREREQ_PM} = {
            %{ $params{PREREQ_PM} || {} },
            %{ $params{BUILD_REQUIRES}},
        };
        delete $params{BUILD_REQUIRES};
    }

    delete $params{CONFIGURE_REQUIRES} if $mm_version < 6.52;
    delete $params{MIN_PERL_VERSION} if $mm_version < 6.48;
    delete $params{META_MERGE} if $mm_version < 6.46;
    delete $params{META_ADD} if $mm_version < 6.46;
    delete $params{LICENSE} if $mm_version < 6.31;
    delete $params{AUTHOR} if $] < 5.005;
    delete $params{ABSTRACT_FROM} if $] < 5.005;
    delete $params{BINARY_LOCATION} if $] < 5.005;

    WriteMakefile(%params);

    write_test_config('test.config' =>
        {
            network_tests => $opt{'live-tests'}
        }
    );
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

sub write_test_config {
    my $file = shift;
    my $config = shift;

    file($file)->spew(
        [
            map sprintf("%s\t%s\n", $_, $config->{$_}), sort keys %$config
        ]
    );
    return;
}

sub show_cmd_output {
    my ($cmd) = @_;
    my $sep = '=' x 80 . "\n";

    my $output = `$cmd`;

    print $sep,
        defined($output) ? "Output from '$cmd':\n$output"
                         : "No output from '$cmd'",
        $sep
    ;

    return;
}

sub build_openssl_version {
    my $source = shift;
    my $opt = shift;

    my $builder = ExtUtils::CBuilder->new;

    my $object = $builder->compile(
        source => $source,
        $opt->{incpath} ? (include_dirs => "$opt->{incpath}") : (),
    );

    my $executable = $builder->link_executable(
        objects => $object,
    );

    return file($executable)->absolute->resolve;
}

