/*
 * $Id: SSLeay.xs,v 1.3 1998/10/13 11:18:12 aas Exp $
 *
 * Copyright 1998 Gisle Aas.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the same terms as Perl itself.
 */

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ssl.h"
#include "crypto.h"
#undef Free /* undo namespace pollution from crypto.h */

#ifdef __cplusplus
}
#endif

#if SSLEAY_VERSION_NUMBER >= 0x0800
#define SSLEAY8
#endif


MODULE = Crypt::SSLeay		PACKAGE = Crypt::SSLeay

PROTOTYPES: DISABLE

MODULE = Crypt::SSLeay		PACKAGE = Crypt::SSLeay::CTX	PREFIX = SSL_CTX_

SSL_CTX*
SSL_CTX_new(packname)
     SV* packname
     CODE:
#ifdef SSLEAY8
	RETVAL = SSL_CTX_new(SSLv2_client_method());
	printf("CTX=%ld\n", RETVAL);
#else
	RETVAL = SSL_CTX_new();
#endif
     OUTPUT:
	RETVAL

void
SSL_CTX_free(ctx)
     SSL_CTX* ctx

int
SSL_CTX_set_cipher_list(ctx, ciphers)
     SSL_CTX* ctx
     char* ciphers


MODULE = Crypt::SSLeay		PACKAGE = Crypt::SSLeay::Conn	PREFIX = SSL_

SSL*
SSL_new(packname, ctx, ...)
	SV* packname
	SSL_CTX* ctx
	CODE:
	   RETVAL = SSL_new(ctx);
	   if (items > 2) {
	       PerlIO* io = IoIFP(sv_2io(ST(2)));
#ifdef _WIN32
	       SSL_set_fd(RETVAL, _get_osfhandle(PerlIO_fileno(io)));
#else
	       SSL_set_fd(RETVAL, PerlIO_fileno(io));
#endif
           }
	OUTPUT:
	   RETVAL


void
SSL_free(ssl)
	SSL* ssl

int
SSL_set_fd(ssl,fd)
	SSL* ssl
	int  fd

int
SSL_connect(ssl)
	SSL* ssl

int
SSL_accept(ssl)
	SSL* ssl

SV*
SSL_write(ssl, buf, ...)
	SSL* ssl
	PREINIT:
	   STRLEN blen;
	   int len;
	   int offset = 0;
	   int n;
	INPUT:
	   char* buf = SvPV(ST(1), blen);
	CODE:
	   if (items > 2) {
	       len = SvOK(ST(2)) ? SvIV(ST(2)) : blen;
	       if (items > 3) {
	           offset = SvIV(ST(3));
	           if (offset < 0) {
		       if (-offset > blen)
			   croak("Offset outside string");
		       offset += blen;
		   } else if (offset >= blen && blen > 0)
		       croak("Offset outside string");
               }
	       if (len > blen - offset)
		   len = blen - offset;
	   } else {
	       len = blen;
           }
	   n = SSL_write(ssl, buf+offset, len);
	   if (n >= 0) {
	       RETVAL = newSViv(n);
	   } else {
	       RETVAL = &sv_undef;
           }
	OUTPUT:
	   RETVAL
	

SV*
SSL_read(ssl, buf, len,...)
	SSL* ssl
	int len
	PREINIT:
	   char *buf;
	   STRLEN blen;
	   int offset = 0;
	   int n;
	INPUT:
	   SV* sv = ST(1);
	CODE:
	   buf = SvPV_force(sv, blen);
	   if (items > 3) {
	       offset = SvIV(ST(3));
	       if (offset < 0) {
		   if (-offset > blen)
		       croak("Offset outside string");
		   offset += blen;
	       }
	       /* this is not a very efficient method of appending
                * (offset - blen) NUL bytes, but it will probably
                * seldom happen.
                */
	       while (offset > blen) {
		   sv_catpvn(sv, "\0", 1);
	           blen++;
               }
	   }
           if (len < 0)
	       croak("Negative length");
	
	   SvGROW(sv, offset + len + 1);
	   buf = SvPVX(sv);  /* it might have been relocated */

	   n = SSL_read(ssl, buf+offset, len);

	   if (n >= 0) {
               SvCUR_set(sv, offset + n);
               buf[offset + n] = '\0';
	       RETVAL = newSViv(n);
	   } else {
	       RETVAL = &sv_undef;
           }

	OUTPUT:
	   RETVAL

X509*
SSL_get_peer_certificate(ssl)
	SSL* ssl

char*
SSL_get_shared_ciphers(ssl)
	SSL* ssl
	PREINIT:
	   char buf[512];
	CODE:
	   RETVAL = SSL_get_shared_ciphers(ssl, buf, sizeof(buf));
	OUTPUT:
	   RETVAL

char*
SSL_get_cipher(ssl)
	SSL* ssl


MODULE = Crypt::SSLeay		PACKAGE = Crypt::SSLeay::X509	PREFIX = X509_

SV*
subject_name(cert)
	X509* cert
	PREINIT:
	   char* str;
	CODE:
#ifdef SSLEAY8
	   str = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
#else
	   str = X509_NAME_oneline(X509_get_subject_name(cert));
#endif
	   RETVAL = newSVpv(str, 0);
	   free(str);
	OUTPUT:
	   RETVAL

SV*
issuer_name(cert)
	X509* cert
	PREINIT:
	   char* str;
	CODE:
#ifdef SSLEAY8
	   str = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
#else
	   str = X509_NAME_oneline(X509_get_issuer_name(cert));
#endif
	   RETVAL = newSVpv(str, 0);
	   free(str);
	OUTPUT:
	   RETVAL
