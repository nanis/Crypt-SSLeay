#!/usr/local/bin/perl

use strict;
use ExtUtils::MakeMaker;
use File::Basename qw(dirname basename);

my $currdir = dirname($0) || '.';
chdir($currdir) || die("can't change to $currdir: $!");

my @POSSIBLE_SSL_DIRS = qw(/usr/local/openssl /usr/local/ssl /local/ssl /opt/ssl /local /usr);
my @CANDIDATE;
my $open_ssl = 0;
my $dir;
for $dir (@POSSIBLE_SSL_DIRS) {
    next unless -d $dir;
    my $candidate = Candidate($dir);
    next unless $candidate;

    push(@CANDIDATE, $candidate);
}

if (@CANDIDATE == 1) {
    my($dir, $inc_dir, $ver) = @{$CANDIDATE[0]};
    print "Found SSLeay (version $ver) installed at $dir\n";
} elsif (@CANDIDATE > 1) {
    print "Found the following SSLeay installations:\n";
    for (@CANDIDATE) {
	my($dir, $inc_dir, $ver) = @$_;
	print "\t$ver\t$dir\n";
    }
}

my $SSL_DIR = shift || prompt "Which SSLeay do you want to link against?", $CANDIDATE[0][0];
my $candidate = &Candidate($SSL_DIR);
unless($candidate) {
    warn "Apparently no SSLeay installation at '$SSL_DIR'\nAre you sure you got it correct????\n"
      unless -f "$SSL_DIR/include/ssl.h";
}
$candidate ||= ["$SSL_DIR", "$SSL_DIR/include"];

my($SEP, $SSL_LIB, $SSL_INC, $LIBS);
$SSL_INC = "$SSL_DIR/include";
"-lssl -lcrypto -lssleay32 -llibeay32";
if($^O =~ /Win32/) {
    unless($SSL_DIR =~ /^[a-zA-Z]\:/) {
	# default drive c
	$SSL_DIR = "c:".$SSL_DIR;
    }
    unless($SSL_INC =~ /^[a-zA-Z]\:/) {
	# default drive c
	$SSL_INC = "c:".$SSL_INC;
    }
    $SSL_DIR =~ s|/|\\|g;
    $SSL_INC =~ s|/|\\|g;
    $SSL_LIB = "-L".$SSL_DIR."\\lib";
    $SEP = "\\";
    $LIBS = "-lssleay32 -llibeay32 -lRSAglue -lrsaref";
} else {
    $SSL_LIB = "-L".$SSL_DIR."/lib";
    $SEP = "/";
    $LIBS = "-lssl -lcrypto -lgcc -lRSAglue -lrsaref";
}

# write include file that determing ssl support
my $ssl_header_prefix = '';
my $client_method;
if($candidate->[2] =~ /openssl/i) {
    $ssl_header_prefix = "openssl/";
#    $client_method = "SSLv23_client_method()";
#    $client_method = "SSLv3_client_method()";
    $client_method = "SSLv2_client_method()";
} else {
    $client_method = "SSLv2_client_method()";
}    

## we need to include crypto.h for SSLeay so the version gets
## picked up in SSLeay.xs
open(INCLUDE, ">crypt_ssleay_version.h") || die("can't open crypt_ssleay_version.h for writing: $!");
print INCLUDE "#include \"".$ssl_header_prefix."ssl.h\"\n";
print INCLUDE "#include \"".$ssl_header_prefix."crypto.h\"\n";
close INCLUDE;

# print  INCLUDE "#define CRYPT_SSL_CLIENT_METHOD $client_method\n";
# client method:	$client_method

print <<INFO;

========================================
BUILD INFORMATION
========================================

ssl dir:	$SSL_DIR
libraries:      $LIBS
include dir:	$SSL_INC
ssl header:     @{[$ssl_header_prefix]}ssl.h

========================================

INFO
  ;

# set the path for testing
$ENV{PATH} = "$SSL_LIB:$ENV{PATH}";

WriteMakefile(
    NAME    => 'Crypt::SSLeay',
    VERSION_FROM => 'SSLeay.pm',
    LIBS    => ["$SSL_LIB $LIBS"],
    INC     => "-I".$SSL_INC,
    dist    => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
);
exit;

## HELPERS

sub Candidate {
    my $dir = shift;
    my $version_file;
    my $inc_dir;

    for ("$dir/include/openssl/opensslv.h", "$dir/include/opensslv.h", "$dir/include/crypto.h") {
	if(-e $_) {
	    $version_file = $_;
	}
    }
    $open_ssl = ($version_file =~ /openssl/) ? 1 : 0;
    my $dirname = $inc_dir = dirname($version_file);
    return unless (-e "$dirname/ssl.h");

    open(VERSION_FILE, $version_file) or return;
    my $version_match = $open_ssl ? "OPENSSL_VERSION_NUMBER" : "SSLEAY_VERSION_NUMBER";
    my $version;
    while (<VERSION_FILE>) {
	if (/^\#define\s+$version_match\s+0x0+(\d\d\d)/) {
	    $version = $1;
	    $version =~ s/(\d)0(\d)/$1$2/;	    
	    my $type = ($version > 92) ? "OpenSSL" : "SSLeay";
	    $version = "$type ".join('.', split(//, "0$version"));
	    last;
	}
    }
    close(VERSION_FILE);

    # Silly test to look for the library files
    my $foundlib = 0;
    if (opendir(LIBDIR, "$dir/lib")) {
	while (defined($_ = readdir(LIBDIR))) {
	   $foundlib++ if /^libssl/;
	   $foundlib++ if /^libcrypto/;
	   $foundlib++ if /^ssleay32/;
	   $foundlib++ if /^libeay32/;
	}
	closedir(LIBDIR);
    }
    warn "$dir/lib does not seem to contain the SSLeay library files\n"
	unless $foundlib;

    [$dir, $inc_dir, $version];
}


