use strict;
use ExtUtils::MakeMaker;

my @POSSIBLE_SSL_DIRS = qw(/local/ssl /usr/local/ssl /opt/ssl /local /usr);
push(@POSSIBLE_SSL_DIRS, "/local/ssl8") if getlogin() eq "aas";

my @CANDIDATE;
my $dir;
for $dir (@POSSIBLE_SSL_DIRS) {
    next unless -f "$dir/include/ssl.h";
    open(CRYPTO, "$dir/include/crypto.h") or next;
    my $version;
    while (<CRYPTO>) {
	if (/^\#define\s+SSLEAY_VERSION_NUMBER\s+0x(\d\d)(\d\d)/) {
	    $version = "$1.$2";
	    last;
	}
    }
    close(CRYPTO);

    # Silly test to look for the library files
    my $foundlib = 0;
    if (opendir(LIBDIR, "$dir/lib")) {
	while (defined($_ = readdir(LIBDIR))) {
	   $foundlib++ if /^libssl/;
	   $foundlib++ if /^libcrypto/;
	}
	closedir(LIBDIR);
    }
    warn "$dir/lib does not seem to contain the SSLeay library files\n"
	unless $foundlib;

    push(@CANDIDATE, [$dir, $version]);
}

if (@CANDIDATE == 1) {
    my($dir, $ver) = @{$CANDIDATE[0]};
    print "Found SSLeay (version $ver) installed at $dir\n";
} elsif (@CANDIDATE > 1) {
    print "Found the following SSLeay installations:\n";
    for (@CANDIDATE) {
	my($dir, $ver) = @$_;
	print "\tv$ver $dir\n";
    }
}

my $SSL_DIR = shift || prompt "Which SSLeay to link to? ", $CANDIDATE[0][0];

warn "Apparently no SSLeay installation at '$SSL_DIR'\nAre you sure you got it correct????\n"
    unless -f "$SSL_DIR/include/ssl.h";

WriteMakefile(
    NAME    => 'Crypt::SSLeay',
    VERSION_FROM => 'SSLeay.pm',
    LIBS    => ["-L$SSL_DIR/lib -lssl -lcrypto"],
    INC     => "-I$SSL_DIR/include",
    dist    => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
);
