use 5.006;
use strict;
use warnings;

use ExtUtils::CBuilder;
use ExtUtils::MakeMaker;
use File::Spec::Functions qw( catfile );
use Getopt::Long;

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

my ($opt_static, $opt_live_tests);

GetOptions(
    'static',      \$opt_static,
    'live-tests!', \$opt_live_tests,
);

$opt_live_tests ||= $ENV{CRYPT_SSLEAY_LIVE_TEST_WANTED};
$opt_live_tests ||= is_live_test_wanted();

my $test_config = 'test.config';

show_cmd_output('openssl version -a');

my $my_openssl_version_cmd = eval {
    build_openssl_version('openssl-version.c')
};

unless (defined $my_openssl_version_cmd) {
    print "Failed to build and link a simple executable using OpenSSL:\n$_\n";
    exit 0;
};

show_cmd_output($my_openssl_version_cmd);

WriteMakefile1(
    META_MERGE => {
        resources => {
            repository => 'https://github.com/nanis/Crypt-SSLeay',
        },
    },

    NAME => 'Crypt::SSLeay',

    AUTHOR => \@authors,

    ABSTRACT_FROM => 'SSLeay.pm',

    VERSION_FROM => 'SSLeay.pm',

    LIBS => [q{-lssl -lcrypto -lssl32 -lssleay32 -leay32 -lz}],

    ($opt_static ? (LINK_TYPE => 'static') : ()),

    TEST_REQUIRES => {
        'Try::Tiny' => '0.09',
        'Test::More' => '0.88',
    },

    CONFIGURE_REQUIRES => {
        'File::Spec' => 0,
        'ExtUtils::CBuilder' => '0.280205',
    },

    PREREQ_PM => {
        'LWP::Protocol::https' => '6.02',
        'MIME::Base64' => 0, # for Net::SSL
    },

    clean => {
        FILES => "$test_config *.o $my_openssl_version_cmd",
    },

    LICENSE => 'artistic_2',

    MIN_PERL_VERSION => 5.006,
);

write_test_config($test_config, {network_tests => $opt_live_tests});

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
    my ($file, $config) = @_;

    open my $out, '>', $file
        or die "Cannot open '$file' for writing: $!";

    for my $key (sort keys %$config) {
        printf $out "%s\t%s\n", $key, $config->{$key};
    }

    close $out
        or die "Cannot close '$file': $!";

    return;
}

sub show_cmd_output {
    my ($cmd) = @_;
    my $sep = '=' x 80 . "\n";

    my $output = `$cmd`;

    print
        $sep,
        defined($output)
        ? "Output from '$cmd':\n$output"
        : "No output from '$cmd'",
        $sep
    ;

    return;
}

sub build_openssl_version {
    my ($source) = @_;

    my $builder = ExtUtils::CBuilder->new;
    my $object = $builder->compile(source => $source);
    my $executable = $builder->link_executable(objects => $object);

    return catfile('.', $executable);
}


sub WriteMakefile1 {  #Compatibility code for old versions of EU::MM. Written by Alexandr Ciornii, version 0.23. Added by eumm-upgrade.
    my %params=@_;
    my $eumm_version=$ExtUtils::MakeMaker::VERSION;
    $eumm_version=eval $eumm_version;
    die "EXTRA_META is deprecated" if exists $params{EXTRA_META};
    die "License not specified" if not exists $params{LICENSE};
    if ($params{AUTHOR} and ref($params{AUTHOR}) eq 'ARRAY' and $eumm_version < 6.5705) {
        $params{META_ADD}->{author}=$params{AUTHOR};
        $params{AUTHOR}=join(', ',@{$params{AUTHOR}});
    }
    if ($params{TEST_REQUIRES} and $eumm_version < 6.64) {
        $params{BUILD_REQUIRES}={ %{$params{BUILD_REQUIRES} || {}} , %{$params{TEST_REQUIRES}} };
        delete $params{TEST_REQUIRES};
    }
    if ($params{BUILD_REQUIRES} and $eumm_version < 6.5503) {
        #EUMM 6.5502 has problems with BUILD_REQUIRES
        $params{PREREQ_PM}={ %{$params{PREREQ_PM} || {}} , %{$params{BUILD_REQUIRES}} };
        delete $params{BUILD_REQUIRES};
    }
    delete $params{CONFIGURE_REQUIRES} if $eumm_version < 6.52;
    delete $params{MIN_PERL_VERSION} if $eumm_version < 6.48;
    delete $params{META_MERGE} if $eumm_version < 6.46;
    delete $params{META_ADD} if $eumm_version < 6.46;
    delete $params{LICENSE} if $eumm_version < 6.31;
    delete $params{AUTHOR} if $] < 5.005;
    delete $params{ABSTRACT_FROM} if $] < 5.005;
    delete $params{BINARY_LOCATION} if $] < 5.005;

    WriteMakefile(%params);
}

