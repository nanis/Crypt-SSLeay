/* Copyright (c) 2010-2014 A. Sinan Unur <nanis@cpan.org>
 * Copyright (c) 2006-2007 David Landgren
 * Copyright (c) 1999-2003 Joshua Chamas
 * Copyright (c) 1998 Gisle Aas
 *
 * This library is free software. You can use, and distribute it under the
 * terms of Artistic License version 2.0:
 * http://www.perlfoundation.org/artistic_license_2_0
 *
 */

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"

#include "XSUB.h"

/* build problem under openssl 0.9.6 and some builds of perl 5.8.x */
#ifndef PERL5
#define PERL5 1
#endif

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define CRYPT_SSLEAY_free OPENSSL_free

#undef Free /* undo namespace pollution from crypto.h */
#ifdef __cplusplus
}
#endif

/* See https://www.openssl.org/docs/ssl/SSL_CTX_new.html
 * The list of protocols available can later be limited using the
 * SSL_OP_NO_SSLv2, SSL_OP_NO_SSLv3, SSL_OP_NO_TLSv1, SSL_OP_NO_TLSv1_1 and
 * SSL_OP_NO_TLSv1_2 options of the SSL_CTX_set_options() or
 * SSL_set_options() functions.
 */

#define CRYPT_SSL_CLIENT_METHOD SSLv23_client_method()

/* https://www.openssl.org/docs/ssl/SSL_CTX_set_msg_callback.html */
static void
msg_callback(
    int write_p,
    int version,
    int content_type,
    const void *buf,
    size_t len,
    SSL *ssl,
    void *arg
) {
    size_t i = 0;
    BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    const char *rw = write_p ? "Sent" : "Received";
    const char *vstr = (version == TLS1_2_VERSION) ? "TLSv1.2"
                     : (version == TLS1_1_VERSION) ? "TLSv1.1"
                     : (version == TLS1_VERSION) ? "TLSv1"
                     : (version == SSL3_VERSION) ? "SSLv3"
                     : (version == SSL2_VERSION) ? "SSLv2"
                     : "unknown protocol"
    ;
    const char *ctstr = (content_type == 20) ? "change_cipher_spec"
                      : (content_type == 21) ? "alert"
                      : (content_type == 22) ? "handshake"
                      : "unknown content type"
    ;
    BIO_printf(bio_err,
        "%s %s %d (%s):",
        vstr, rw, content_type, ctstr
    );
    for (i = 0; i < len; i += 1) {
        BIO_printf(bio_err, " %02x", ((unsigned char *) buf)[i]);
    }
    BIO_puts(bio_err, "\n");

    if (content_type == 20) {
        char buf[256];
        const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
        if (cipher) {
            if (SSL_CIPHER_description(cipher, buf, 256)) {
                buf[255] = 0;
                BIO_puts(bio_err, buf);
                BIO_puts(bio_err, "\n");
            }
        }
    }
    BIO_free(bio_err);
    return;
}

static void
info_callback(const SSL *s, int where, int ret) {
    BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    int w = where & ~SSL_ST_MASK;
    const char *mode = (w & SSL_ST_CONNECT) ? "SSL_connect"
                     : (w & SSL_ST_ACCEPT)  ? "SSL_accept"
                     : "unknown"
    ;

    if (where & SSL_CB_LOOP) {
        BIO_printf(bio_err, "%s: %s\n", mode, SSL_state_string_long(s));
        goto LAST;
    }

    if (where & SSL_CB_ALERT) {
        BIO_printf(
            bio_err, "SSL/TLS alert %s: %s: %s\n",
            (where & SSL_CB_READ) ? "read" : "write",
            SSL_alert_type_string_long(ret),
            SSL_alert_desc_string_long(ret)
        );
        goto LAST;
    }

    if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            BIO_printf(
                bio_err, "%s: failed in %s\n",
                mode,  SSL_state_string_long(s)
            );
            goto LAST;
        }
        if (ret < 0) {
            BIO_printf(
                bio_err, "%s:error in %s\n",
                mode, SSL_state_string_long(s)
            );
            goto LAST;
        }
    }
    LAST:
        BIO_free(bio_err);
        return;
}


MODULE = Crypt::SSLeay                PACKAGE = Crypt::SSLeay

PROTOTYPES: DISABLE

MODULE = Crypt::SSLeay         PACKAGE = Crypt::SSLeay::Err PREFIX = ERR_

#define CRYPT_SSLEAY_ERR_BUFSIZE 1024

const char *
ERR_get_error_string()
    PREINIT:
        unsigned long code;
        char buf[ CRYPT_SSLEAY_ERR_BUFSIZE ];

    CODE:
        if ((code = ERR_get_error()) == 0) {
            RETVAL = NULL;
        }
        else {
            /* www.openssl.org/docs/crypto/ERR_error_string.html */
            ERR_error_string_n(code, buf, CRYPT_SSLEAY_ERR_BUFSIZE);
            RETVAL = buf;
        }
    OUTPUT:
        RETVAL

MODULE = Crypt::SSLeay    PACKAGE = Crypt::SSLeay::CTX    PREFIX = SSL_CTX_

#define CRYPT_SSLEAY_RAND_BUFSIZE 1024

SSL_CTX *
SSL_CTX_new(package, allow_sslv3)
     SV *package
     int allow_sslv3
     CODE:
        SSL_CTX *ctx;
        static int bNotFirstTime;

        if(!bNotFirstTime) {
            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();
            ERR_load_crypto_strings();
            SSL_library_init();
            bNotFirstTime = 1;
        }

        /* Add to entropy using Bytes::Random::Secure::random_bytes
         * See also http://security.stackexchange.com/questions/56469/
         */
        do {
            dSP;
            int count;
            SV *random_bytes;

            ENTER;
            SAVETMPS;
            PUSHMARK(SP);
            XPUSHs(sv_2mortal(newSViv(CRYPT_SSLEAY_RAND_BUFSIZE)));
            PUTBACK;
            count = call_pv("Bytes::Random::Secure::random_bytes", G_SCALAR);
            SPAGAIN;
            if (count != 1) {
                croak("Failed to get random bytes\n");
            }
            random_bytes = POPs;
            RAND_seed(
                SvPVbyte_nolen(random_bytes),
                CRYPT_SSLEAY_RAND_BUFSIZE
            );
            PUTBACK;
            FREETMPS;
            LEAVE;
        } while (0);

        ctx = SSL_CTX_new(CRYPT_SSL_CLIENT_METHOD);
        if (allow_sslv3) {
            SSL_CTX_set_options(ctx,
                SSL_OP_ALL |
                SSL_OP_NO_SSLv2
            );
        }
        else {
            SSL_CTX_set_options(ctx,
                SSL_OP_ALL |
                SSL_OP_NO_SSLv2 |
                SSL_OP_NO_SSLv3
            );
        }

        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        RETVAL = ctx;
     OUTPUT:
        RETVAL

void
SSL_CTX_free(ctx)
     SSL_CTX *ctx

int
SSL_CTX_set_cipher_list(ctx, ciphers)
     SSL_CTX *ctx
     char *ciphers

int
SSL_CTX_use_certificate_file(ctx, filename, mode)
     SSL_CTX *ctx
     char *filename
     int mode

int
SSL_CTX_use_PrivateKey_file(ctx, filename ,mode)
     SSL_CTX *ctx
     char *filename
     int mode

int
SSL_CTX_use_pkcs12_file(ctx, filename, password)
     SSL_CTX *ctx
     const char *filename
     const char *password
     PREINIT:
        FILE *fp;
        EVP_PKEY *pkey;
        X509 *cert;
        STACK_OF(X509) *ca = NULL;
        PKCS12 *p12;
     CODE:
        if ((fp = fopen(filename, "rb"))) {
            p12 = d2i_PKCS12_fp(fp, NULL);
            fclose (fp);

            if (p12) {
                if(PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
                    if (pkey) {
                        RETVAL = SSL_CTX_use_PrivateKey(ctx, pkey);
                        EVP_PKEY_free(pkey);
                    }
                    if (cert) {
                        RETVAL = SSL_CTX_use_certificate(ctx, cert);
                        X509_free(cert);
                    }
                }
                PKCS12_free(p12);
            }
        }
     OUTPUT:
        RETVAL


int
SSL_CTX_check_private_key(ctx)
     SSL_CTX *ctx

SV *
SSL_CTX_set_verify(ctx)
     SSL_CTX *ctx
     PREINIT:
        char *CAfile;
        char *CAdir;
     CODE:
        CAfile=getenv("HTTPS_CA_FILE");
        CAdir =getenv("HTTPS_CA_DIR");

        if(!CAfile && !CAdir) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
            RETVAL = newSViv(0);
        }
        else {
            SSL_CTX_load_verify_locations(ctx,CAfile,CAdir);
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            RETVAL = newSViv(1);
        }
     OUTPUT:
       RETVAL

MODULE = Crypt::SSLeay        PACKAGE = Crypt::SSLeay::Conn        PREFIX = SSL_

SSL *
SSL_new(package, ctx, debug, ...)
    SV *package
    SSL_CTX *ctx
    SV *debug

    PREINIT:
        SSL *ssl;

    CODE:
        ssl = SSL_new(ctx);
        SSL_set_connect_state(ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        if (SvTRUE(debug)) {
            SSL_set_info_callback(ssl, info_callback);
            SSL_set_msg_callback(ssl, msg_callback);
        }

        if (items > 2) {
            PerlIO *io = IoIFP(sv_2io(ST(3)));
#ifdef _WIN32
            /* PROBLEM:
             * _get_osfhandle returns intptr_t but the OpenSSL set_fd
             * takes an int as the fd argument. see
             * https://www.openssl.org/docs/manmaster/man3/SSL_set_fd.html
             * https://msdn.microsoft.com/en-us/library/ks2530z6.aspx
             */
            int fd = _get_osfhandle(PerlIO_fileno(io));
#else
            int fd = PerlIO_fileno(io);
#endif
            SSL_set_fd(ssl, fd);
        }
        RETVAL = ssl;

        OUTPUT:
            RETVAL

void
SSL_free(ssl)
        SSL *ssl

int
SSL_pending(ssl)
        SSL *ssl

int
SSL_set_fd(ssl,fd)
        SSL *ssl
        int  fd

int
SSL_connect(ssl)
        SSL *ssl

int
SSL_accept(ssl)
        SSL *ssl

SV *
SSL_write(ssl, buf, ...)
        SSL *ssl
        PREINIT:
           STRLEN blen;
           int len;
           int offset = 0;
           int keep_trying_to_write = 1;
        INPUT:
           char *buf = SvPV(ST(1), blen);
        CODE:
           if (items > 2) {
               len = SvOK(ST(2)) ? SvIV(ST(2)) : blen;
               if (items > 3) {
                   offset = SvIV(ST(3));
                   if (offset < 0) {
                       if (-offset > blen)
                           croak("Offset outside string");
                       offset += blen;
                   }
                   else if (offset >= blen && blen > 0)
                       croak("Offset outside string");
               }
               if (len > blen - offset)
                   len = blen - offset;
           }
           else {
               len = blen;
           }

           /* try to handle incomplete writes properly
            * see RT bug #64054 and RT bug #78695
            * 2012/08/02: Stop trying to distinguish between good & bad
            * zero returns from underlying SSL_read/SSL_write
            */
           while (keep_trying_to_write)
           {
                int n = SSL_write(ssl, buf+offset, len);
                int x = SSL_get_error(ssl, n);

                if ( n >= 0 )
                {
                    keep_trying_to_write = 0;
                    RETVAL = newSViv(n);
                }
                else
                {
                    if
                    (
                        (x != SSL_ERROR_WANT_READ) &&
                        (x != SSL_ERROR_WANT_WRITE)
                    )
                    {
                        keep_trying_to_write = 0;
                        RETVAL = &PL_sv_undef;
                    }
                }
           }
        OUTPUT:
           RETVAL

SV *
SSL_read(ssl, buf, len,...)
        SSL *ssl
        int len
        PREINIT:
           char *buf;
           STRLEN blen;
           int offset = 0;
           int keep_trying_to_read = 1;
        INPUT:
           SV *sv = ST(1);
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

           /* try to handle incomplete writes properly
            * see RT bug #64054 and RT bug #78695
            * 2012/08/02: Stop trying to distinguish between good & bad
            * zero returns from underlying SSL_read/SSL_write
            */
           while (keep_trying_to_read) {
                int n = SSL_read(ssl, buf+offset, len);
                int x = SSL_get_error(ssl, n);

                if ( n >= 0 )
                {
                    SvCUR_set(sv, offset + n);
                    buf[offset + n] = '\0';
                    keep_trying_to_read = 0;
                    RETVAL = newSViv(n);
                }
                else
                {
                    if
                    (
                        (x != SSL_ERROR_WANT_READ) &&
                        (x != SSL_ERROR_WANT_WRITE)
                    )
                    {
                        keep_trying_to_read = 0;
                        RETVAL = &PL_sv_undef;
                    }
                }
           }
        OUTPUT:
           RETVAL

X509 *
SSL_get_peer_certificate(ssl)
        SSL *ssl

SV *
SSL_get_verify_result(ssl)
        SSL *ssl
        CODE:
           RETVAL = newSViv((SSL_get_verify_result(ssl) == X509_V_OK) ? 1 : 0);
        OUTPUT:
           RETVAL

#define CRYPT_SSLEAY_SHARED_CIPHERS_BUFSIZE 512

char *
SSL_get_shared_ciphers(ssl)
    SSL *ssl
    PREINIT:
        char buf[ CRYPT_SSLEAY_SHARED_CIPHERS_BUFSIZE ];
    CODE:
        RETVAL = SSL_get_shared_ciphers(
                    ssl, buf, CRYPT_SSLEAY_SHARED_CIPHERS_BUFSIZE
                 );
    OUTPUT:
        RETVAL

char *
SSL_get_cipher(ssl)
        SSL *ssl
        CODE:
           RETVAL = (char *) SSL_get_cipher(ssl);
        OUTPUT:
           RETVAL

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)

void
SSL_set_tlsext_host_name(ssl, name)
        SSL *ssl
        const char *name

#endif

MODULE = Crypt::SSLeay        PACKAGE = Crypt::SSLeay::X509        PREFIX = X509_

void
X509_free(cert)
       X509 *cert

SV *
subject_name(cert)
        X509 *cert
        PREINIT:
           char *str;
        CODE:
           str = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
           RETVAL = newSVpv(str, 0);
           CRYPT_SSLEAY_free(str);
        OUTPUT:
           RETVAL

SV *
issuer_name(cert)
        X509 *cert
        PREINIT:
           char *str;
        CODE:
           str = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
           RETVAL = newSVpv(str, 0);
           CRYPT_SSLEAY_free(str);
        OUTPUT:
           RETVAL

char *
get_notBeforeString(cert)
         X509 *cert
         CODE:
            RETVAL = (char *)X509_get_notBefore(cert)->data;
         OUTPUT:
            RETVAL

char *
get_notAfterString(cert)
         X509 *cert
         CODE:
            RETVAL = (char *)X509_get_notAfter(cert)->data;
         OUTPUT:
            RETVAL

MODULE = Crypt::SSLeay      PACKAGE = Crypt::SSLeay::Version    PREFIX = VERSION_

const char *
VERSION_openssl_version()
    CODE:
        RETVAL = SSLeay_version(SSLEAY_VERSION);
    OUTPUT:
        RETVAL

long
VERSION_openssl_version_number()
    CODE:
        RETVAL = OPENSSL_VERSION_NUMBER;
    OUTPUT:
        RETVAL

const char *
VERSION_openssl_cflags()
    CODE:
        RETVAL = SSLeay_version(SSLEAY_CFLAGS);
    OUTPUT:
        RETVAL

const char *
VERSION_openssl_platform()
    CODE:
        RETVAL = SSLeay_version(SSLEAY_PLATFORM);
    OUTPUT:
        RETVAL

const char *
VERSION_openssl_built_on()
    CODE:
        RETVAL = SSLeay_version(SSLEAY_BUILT_ON);
    OUTPUT:
        RETVAL

const char *
VERSION_openssl_dir()
    CODE:
        RETVAL = SSLeay_version(SSLEAY_DIR);
    OUTPUT:
        RETVAL

