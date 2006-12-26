package Crypt::SSLeay;

use Crypt::SSLeay::X509;

use strict;
use vars qw(@ISA $VERSION %CIPHERS);

require DynaLoader;

@ISA = qw(DynaLoader);
$VERSION = '0.53';

bootstrap Crypt::SSLeay $VERSION;

use vars qw(%CIPHERS);
%CIPHERS = (
   'NULL-MD5'     => "No encryption with a MD5 MAC",
   'RC4-MD5'      => "128 bit RC4 encryption with a MD5 MAC",
   'EXP-RC4-MD5'  => "40 bit RC4 encryption with a MD5 MAC",
   'RC2-CBC-MD5'  => "128 bit RC2 encryption with a MD5 MAC",
   'EXP-RC2-CBC-MD5' => "40 bit RC2 encryption with a MD5 MAC",
   'IDEA-CBC-MD5' => "128 bit IDEA encryption with a MD5 MAC",
   'DES-CBC-MD5'  => "56 bit DES encryption with a MD5 MAC",
   'DES-CBC-SHA'  => "56 bit DES encryption with a SHA MAC",
   'DES-CBC3-MD5' => "192 bit EDE3 DES encryption with a MD5 MAC",
   'DES-CBC3-SHA' => "192 bit EDE3 DES encryption with a SHA MAC",
   'DES-CFB-M1'   => "56 bit CFB64 DES encryption with a one byte MD5 MAC",
);


# A xsupp bug made this nessesary
sub Crypt::SSLeay::CTX::DESTROY  { shift->free; }
sub Crypt::SSLeay::Conn::DESTROY { shift->free; }
sub Crypt::SSLeay::X509::DESTROY { shift->free; }

1;

__END__

=head1 NAME

Crypt::SSLeay - OpenSSL glue that provides LWP https support

=head1 SYNOPSIS

  lwp-request https://www.example.com

  use LWP::UserAgent;
  my $ua = new LWP::UserAgent;
  my $req = new HTTP::Request('GET', 'https://www.example.com');
  my $res = $ua->request($req);
  print $res->code."\n";

  # proxy support
  $ENV{HTTPS_PROXY} = 'http://proxy_hostname_or_ip:port';

  # proxy_basic_auth
  $ENV{HTTPS_PROXY_USERNAME} = 'username';
  $ENV{HTTPS_PROXY_PASSWORD} = 'password';  

  # debugging (SSL diagnostics)
  $ENV{HTTPS_DEBUG} = 1;

  # default ssl version
  $ENV{HTTPS_VERSION} = '3';

  # client certificate support
  $ENV{HTTPS_CERT_FILE} = 'certs/notacacert.pem';
  $ENV{HTTPS_KEY_FILE}  = 'certs/notacakeynopass.pem';

  # CA cert peer verification
  $ENV{HTTPS_CA_FILE}   = 'certs/ca-bundle.crt';
  $ENV{HTTPS_CA_DIR}    = 'certs/';

  # Client PKCS12 cert support
  $ENV{HTTPS_PKCS12_FILE}     = 'certs/pkcs12.pkcs12';
  $ENV{HTTPS_PKCS12_PASSWORD} = 'PKCS12_PASSWORD';

=head1 DESCRIPTION

This document describes C<Crypt::SSLeay> version 0.53, released
2006-12-26.

This perl module provides support for the https protocol under LWP,
to allow an C<LWP::UserAgent> object to perform GET, HEAD and POST
requests. Please see LWP for more information on POST requests.

The C<Crypt::SSLeay> package provides C<Net::SSL>, which is loaded
by C<LWP::Protocol::https> for https requests and provides the
necessary SSL glue.

This distribution also makes following deprecated modules available:

  Crypt::SSLeay::CTX
  Crypt::SSLeay::Conn
  Crypt::SSLeay::X509

Work on Crypt::SSLeay has been continued only to
provide https support for the LWP (libwww-perl)
libraries. People wishing to access the OpenSSL API
directly from Perl are advised to look at the
C<Net::SSLeay> module.

  http://search.cpan.org/dist/Net_SSLeay.pm/

=head1 INSTALL

=head2 OpenSSL

You must have OpenSSL or SSLeay installed before compiling 
this module.  You can get the latest OpenSSL package from:

  http://www.openssl.org/

When installing openssl make sure your config looks like:

  > ./config --openssldir=/usr/local/openssl
 or
  > ./config --openssldir=/usr/local/ssl

If you are planning on upgrading the default OpenSSL libraries on 
a system like RedHat, not that I would recommend this, then 
you might try something like:

  > ./config --openssldir=/usr --shared

The --shared option to config will set up building the .so 
shared libraries which is important for such systems.

 then
  > make
  > make test
  > make install

This way Crypt::SSLeay will pick up the includes and 
libraries automatically.  If your includes end up
going into a separate directory like /usr/local/include,
then you may need to symlink /usr/local/openssl/include
to /usr/local/include

=head2 Crypt::SSLeay

The latest Crypt::SSLeay can be found at your nearest CPAN,
and also:

  http://search.cpan.org/dist/Crypt-SSLeay/

Once you have downloaded it, Crypt::SSLeay installs easily 
using the make or nmake commands as shown below.  

  > perl Makefile.PL
  > make
  > make test
  > make install

  * use nmake for win32

  !!! NOTE for Win32 users, few people seem to be able to build
  W  Crypt::SSLeay successfully on that platform.  You don't need
  I  to because ActiveState has already compiled it for you,
  N  and is available for their perl builds 618 & 522 as a ppm
  3  install.  It may also be available for their latest build.
  2  For problems with this, please contact ActiveState.
  !!!          Please see http://www.activestate.com/

=head1 PROXY SUPPORT

LWP::UserAgent and Crypt::SSLeay have their own versions of 
proxy support. Please read these sections to see which one
may be right for you.

=head2 LWP::UserAgent Proxy Support

LWP::UserAgent has its own methods of proxying which may work for
you and is likely to be incompatible with Crypt::SSLeay proxy support.
To use LWP::UserAgent proxy support, try something like:

  my $ua = new LWP::UserAgent;
  $ua->proxy([qw( https http )], "$proxy_ip:$proxy_port");

At the time of this writing, libwww v5.6 seems to proxy https 
requests fine with an Apache mod_proxy server.  It sends a line like:

  GET https://www.example.com HTTP/1.1

to the proxy server, which is not the CONNECT request that
some proxies would expect, so this may not work with other
proxy servers than mod_proxy.  The CONNECT method is used
by Crypt::SSLeay's internal proxy support.

=head2 Crypt::SSLeay Proxy Support

For native Crypt::SSLeay proxy support of https requests,
you need to set an environment variable HTTPS_PROXY to your 
proxy server and port, as in:

  # proxy support
  $ENV{HTTPS_PROXY} = 'http://proxy_hostname_or_ip:port';
  $ENV{HTTPS_PROXY} = '127.0.0.1:8080';

Use of the C<HTTPS_PROXY> environment variable in this way 
is similar to LWP::UserAgent->env_proxy() usage, but calling
that method will likely override or break the Crypt::SSLeay
support, so do not mix the two.

Basic auth credentials to the proxy server can be provided 
this way:

  # proxy_basic_auth
  $ENV{HTTPS_PROXY_USERNAME} = 'username';
  $ENV{HTTPS_PROXY_PASSWORD} = 'password';  

For an example of LWP scripting with Crypt::SSLeay native proxy
support, please look at the F<lwp-ssl-test> script in the 
Crypt::SSLeay distribution.

=head1 CLIENT CERTIFICATE SUPPORT

Client certificates are supported. PEM0encoded certificate and
private key files may be used like this:

  $ENV{HTTPS_CERT_FILE} = 'certs/notacacert.pem';
  $ENV{HTTPS_KEY_FILE}  = 'certs/notacakeynopass.pem';

You may test your files with the F<net_ssl_test> program,
bundled with the distribution, by issuing a command like:

  ./net_ssl_test -cert=certs/notacacert.pem \
	-key=certs/notacakeynopass.pem -d GET $HOST_NAME

Additionally, if you would like to tell the client where
the CA file is, you may set these.

  $ENV{HTTPS_CA_FILE} = "some_file";
  $ENV{HTTPS_CA_DIR}  = "some_dir";

There is no sample CA cert file at this time for testing,
but you may configure ./net_ssl_test to use your CA cert
with the -CAfile option. (TODO: then what is teh ./certs
directory in the distribution??)

=head2 Creating a test certificate

To create simple test certificates with OpenSSL, you may
run the following command:

  openssl req -config /usr/local/openssl/openssl.cnf \
    -new -days 365 -newkey rsa:1024 -x509 \
    -keyout notacakey.pem -out notacacert.pem 

To remove the pass phrase from the key file, run:

  openssl rsa -in notacakey.pem -out notacakeynopass.pem

=head2 PKCS12 support

The directives for enabling use of PKCS12 certificates is:

  $ENV{HTTPS_PKCS12_FILE}     = 'certs/pkcs12.pkcs12';
  $ENV{HTTPS_PKCS12_PASSWORD} = 'PKCS12_PASSWORD';

Use of this type of certificate takes precedence over previous
certificate settings described. (TODO: unclear? Meaning "the
presence of this type of certificate??)

=head1 SSL versions

Crypt::SSLeay tries very hard to connect to I<any> SSL web server
accomodating servers that are buggy, old or simply
not standards-compliant. To this effect, this module will
try SSL connections in this order:

  SSL v23 - should allow v2 and v3 servers to pick their best type
  SSL v3  - best connection type
  SSL v2  - old connection type

Unfortunately, some servers seem not to handle a reconnect
to SSL v3 after a failed connect of SSL v23 is tried,
so you may set before using LWP or Net::SSL:

  $ENV{HTTPS_VERSION} = 3;

so that a SSL v3 connection is tried first. At this time
only a SSL v2 connection will be tried after this, as the 
connection attempt order remains unchanged by this setting.

=head1 BUILD NOTES

=head2 Win32, WinNT, Win2000, can't build

If you cannot get it to build on your windows box, try 
ActiveState perl, at least their builds 522 & 618 are
known to have a ppm install of Crypt::SSLeay available.
Please see http://www.activestate.com for more info.

=head2 AIX 4.3.2 - Symbol Error: __umoddi3 : referenced symbol not found

The __umoddi3 problem applies here as well when compiling with gcc.

Alternative solution:
In Makefile.PL, prepend C<-L>/usr/local/<path to your gcc lib>/<version>
to the $LIBS value. Add after line 82:

 $LIBS = '-L' . dirname(`gcc -print-libgcc-file-name`) . ' ' . $LIBS;

=head2 Solaris x86 - Symbol Error: __umoddi3 : referenced symbol not found

 Problem:

On Solaris x86, the default PERL configuration, and preferred, is to use
the ld linker that comes with the OS, not gcc.  Unfortunately during the 
OpenSSL build process, gcc generates in libcrypto.a, from bn_word.c,
the undefined symbol __umoddi3, which is supposed to be later resolved
by gcc from libgcc.a

The system ld linker does not know about libgcc.a by default, so 
when building Crypt::SSLeay, there is a linker error for __umoddi3

 Solution:

The fix for this symlink your libgcc.a to some standard directory
like /usr/local/lib, so that the system linker, ld, can find
it when building Crypt::SSLeay.  

=head2 FreeBSD 2.x.x / Solaris - ... des.h:96 #error _ is defined ...

If you encounter this error: "...des.h:96: #error _ is
defined, but some strange definition the DES library cannot handle
that...," then you need to edit the des.h file and comment out the 
"#error" line.

Its looks like this error might be common to other operating
systems, and that occurs with OpenSSL 0.9.3.  Upgrades to
0.9.4 seem to fix this problem.

=head2 SunOS 4.1.4, Perl 5.004_04 - ld.so: Undefined symbol: _CRYPT_mem_ctrl

Problems: (initial build was fine, but execution of Perl scripts had problems)

Got a message "ld.so: Undefined symbol: _CRYPT_mem_ctrl"
solution:  In the Makefile, comment out the line with
"-fpic"  (also try changing to "-fPIC", and this works
also, not sure if one is preferred).

=head1 NOTES

Many thanks to Gisle Aas for the original writing of 
this module and many others including libwww for perl.  
The web will never be the same :)

Ben Laurie deserves kudos for his excellent patches
for better error handling, SSL information inspection,
and random seeding.

Thanks to Dongqiang Bai for host name resolution fix when
using a proxy.

Thanks to Stuart Horner of Core Communications, Inc. who found
the need for building --shared OpenSSL libraries.

Thanks to Pavel Hlavnicka for a patch for freeing memory when
using a pkcs12 file, and for inspiring more robust read() behavior.

James Woodyatt is a champ for finding a ridiculous memory
leak that has been the bane of many a Crypt::SSLeay user.

Thanks to Bryan Hart for his patch adding proxy support,
and thanks to Tobias Manthey for submitting another approach.

Thanks to Alex Rhomberg for Alpha linux ccc patch.

Thanks to Tobias Manthey for his patches for client 
certificate support.

Thanks to Daisuke Kuroda for adding PKCS12 certificate
support.

Thanks to Gamid Isayev for CA cert support and 
insights into error messaging.

Thanks to Jeff Long for working through a tricky CA
cert SSLClientVerify issue.

Thanks to Chip Turner for patch to build under perl 5.8.0.

Thanks to Joshua Chamas for the time he spent maintaining the
module.

=head1 SUPPORT

For use of Crypt::SSLeay & Net::SSL with perl's LWP, please
send email to C<libwww@perl.org>.

For OpenSSL or general SSL support please email the 
openssl user mailing list at C<openssl-users@openssl.org>.
This includes issues associated with building and installing
OpenSSL on one's system.

Please report all bugs at
L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Crypt-SSLeay>.

This module was originally written by Gisle Aas, and was subsequently
maintained by Joshua Chamas.

This module is currently maintained by David Landgren.

=head1 COPYRIGHT

 Copyright (c) 2006 David Landgren.
 Copyright (c) 1999-2003 Joshua Chamas.
 Copyright (c) 1998 Gisle Aas.

This program is free software; you can redistribute 
it and/or modify it under the same terms as Perl itself. 

=cut
