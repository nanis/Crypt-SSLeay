package Crypt::SSLeay;

# $Id: SSLeay.pm,v 1.4 1998/01/11 00:09:31 aas Exp $

use strict;
use vars qw(@ISA $VERSION %CIPHERS);

require DynaLoader;

@ISA = qw(DynaLoader);
$VERSION = '0.03';

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
sub Crypt::SSL::CTX::DESTROY  { shift->free; }
sub Crypt::SSL::Conn::DESTROY { shift->free; }

1;
