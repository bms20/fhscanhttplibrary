/*
Copyright (C) 2007 - 2009  fhscan project.
Andres Tarasco - http://www.tarasco.org/security

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:
    This product includes software developed by Andres Tarasco fhscan 
    project and its contributors.
4. Neither the name of the project nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

*/
/*
 SSLModule is an openssl Class that allows calling openssl crypto functions
 from different OS.
*/
#ifndef _SSLMODULE_H_
#define _SSLMODULE_H_
#include "Build.h"
 #include <openssl/crypto.h>
 #include <openssl/x509.h>
 #include <openssl/pem.h>
 #include <openssl/ssl.h>
 #include <openssl/err.h>

 #include <openssl/md2.h>
 #include <openssl/md4.h>
 #include <openssl/md5.h>
 #include <openssl/sha.h>
 #define SSL_CTX_SET_TMP_DH(ctx,dh) \
		 SSL_CTX_CTRL(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)dh)
 #define BIO_GET_MEM_PTR(b,pp)	BIO_CTRL(b,BIO_C_GET_BUF_MEM_PTR,0,(char *)pp)
 #define BIO_FLUSH(b)		(int)BIO_CTRL(b,BIO_CTRL_FLUSH,0,NULL)
 #ifdef BIO_set_flags /* compatibility check with older openssl library */	
	#define BIO_SET_FLAGS_FUNC BIO_set_flags
#endif


	typedef SSL*        (*SSL_NEW_FUNC)(SSL_CTX*);
	typedef void        (*SSL_FREE_FUNC)(SSL*);
	typedef int         (*SSL_SHUTDOWN_FUNC)(SSL*);
	typedef int         (*SSL_READ_FUNC)(SSL*,void*,int);
	typedef int         (*SSL_WRITE_FUNC)(SSL*,const void*,int);
	typedef void        (*SSL_CTX_FREE_FUNC)(SSL_CTX*);
	typedef SSL_CTX*    (*SSL_CTX_NEW_FUNC) (SSL_METHOD*);
	typedef int         (*SSL_CONNECT_FUNC)(SSL*);
	typedef int			(*SSL_GET_ERROR_FUNC) (SSL*,int);
	typedef int         (*SSL_SET_FD_FUNC)(SSL*,int);
	typedef int			(*SSL_PENDING_FUNC)(SSL*);
	typedef SSL_METHOD* (*TLSV1_CLIENT_METHOD_FUNC)(void);
	typedef void		(*SSL_LOAD_ERROR_STRINGS_FUNC)(void);
	typedef int			(*SSL_LIBRARY_INIT_FUNC)(void);
	typedef SSL_METHOD* (*SSLV23_METHOD_FUNC)(void);
	typedef void		(*SSL_CTX_SET_DEFAULT_PASSWD_CB_FUNC)(SSL_CTX*,pem_password_cb*);
	typedef int			(*SSL_ACCEPT_FUNC)(SSL*);
	typedef int			(*SSL_CTX_LOAD_VERIFY_LOCATIONS_FUNC)(SSL_CTX*,const char*, const char *);
	typedef BIO*		(*BIO_NEW_FILE_FUNC)(const char*, const char*);
	typedef int			(*SSL_CTX_USE_CERTIFICATE_CHAIN_FILE_FUNC)(SSL_CTX*,const char*);
	typedef BIO*		(*BIO_NEW_SOCKET_FUNC)(int, int);
	typedef int			(*BIO_FREE_FUNC) (BIO*);
	typedef BIO*		(*BIO_NEW_FP_FUNC)(FILE*,int);
	typedef void		(*SSL_SET_BIO_FUNC) (SSL*,BIO*,BIO*);
	typedef int			(*SSL_CTX_USE_PRIVATEKEY_FILE_FUNC)(SSL_CTX*,const char*,int);
	typedef long		(*SSL_CTX_CTRL_FUNC) (SSL_CTX *,int , long , void *);
	typedef void		(*SSL_CTX_SET_VERIFY_DEPTH_FUNC)(SSL_CTX *,int);
	typedef DH*			(*PEM_READ_BIO_DHPARAMS_FUNC) (BIO*, DH**,int*,void*);
	typedef BIO_METHOD*	(*BIO_F_BASE64_FUNC)(void);
#ifndef BIO_set_flags /* compatibility check with older openssl library */
	typedef int			(*BIO_SET_FLAGS_FUNC)(BIO*,int);
#endif
	typedef BIO*		(*BIO_NEW_FUNC)(BIO_METHOD *);
	typedef int			(*BIO_WRITE_FUNC)(BIO*,const void*, int);
	typedef BIO*		(*BIO_PUSH_FUNC)(BIO*,BIO*);
	typedef int			(*BIO_READ_FUNC)(BIO*,void*,int);
	typedef BIO*		(*BIO_NEW_MEM_BUF_FUNC) (void*,int);
	typedef void		(*BIO_FREE_ALL_FUNC)(BIO*);
	typedef BIO_METHOD*	(*BIO_S_MEM_FUNC)();
	typedef long		(*BIO_CTRL_FUNC)(BIO*,int,long,void*);
	typedef int			(*MD2_INIT_FUNC)(MD2_CTX*);
	typedef int			(*MD2_UPDATE_FUNC)(MD2_CTX*,const void*, unsigned long);
	typedef int			(*MD2_FINAL_FUNC)(unsigned char*, MD2_CTX*);
	typedef int			(*MD4_INIT_FUNC)(MD4_CTX*);
	typedef int			(*MD4_UPDATE_FUNC)(MD4_CTX*,const void*, unsigned long);
	typedef int			(*MD4_FINAL_FUNC)(unsigned char*, MD4_CTX*);
	typedef int			(*MD5_INIT_FUNC)(MD5_CTX*);
	typedef int			(*MD5_UPDATE_FUNC)(MD5_CTX*,const void*, unsigned long);
	typedef int			(*MD5_FINAL_FUNC)(unsigned char*, MD5_CTX*);
	typedef int			(*SHA1_INIT_FUNC)(SHA_CTX*);
	typedef int			(*SHA1_UPDATE_FUNC)(SHA_CTX*,const void*, unsigned long);
	typedef int			(*SHA1_FINAL_FUNC)(unsigned char*, SHA_CTX*);
class SSLModule
{

public:

	SSL_NEW_FUNC                SSL_NEW;
	SSL_FREE_FUNC               SSL_FREE;
	SSL_SHUTDOWN_FUNC           SSL_SHUTDOWN;
	SSL_READ_FUNC               SSL_READ;
	SSL_WRITE_FUNC              SSL_WRITE;
	SSL_CTX_FREE_FUNC           SSL_CTX_FREE;
	SSL_CTX_NEW_FUNC            SSL_CTX_NEW;
	SSL_CONNECT_FUNC            SSL_CONNECT;
	SSL_GET_ERROR_FUNC          SSL_GET_ERROR;
	SSL_SET_FD_FUNC             SSL_SET_FD;
	SSL_PENDING_FUNC            SSL_PENDING;
	TLSV1_CLIENT_METHOD_FUNC    TLSV1_CLIENT_METHOD;
	SSL_LOAD_ERROR_STRINGS_FUNC SSL_LOAD_ERROR_STRINGS;
	SSL_LIBRARY_INIT_FUNC       SSL_LIBRARY_INIT;

	SSLV23_METHOD_FUNC          SSLV23_METHOD;
	SSL_CTX_SET_DEFAULT_PASSWD_CB_FUNC SSL_CTX_SET_DEFAULT_PASSWD_CB;
	SSL_ACCEPT_FUNC             SSL_ACCEPT;
	SSL_CTX_LOAD_VERIFY_LOCATIONS_FUNC SSL_CTX_LOAD_VERIFY_LOCATIONS;
	BIO_NEW_FILE_FUNC           BIO_NEW_FILE;
	SSL_CTX_USE_CERTIFICATE_CHAIN_FILE_FUNC	SSL_CTX_USE_CERTIFICATE_CHAIN_FILE;
	BIO_NEW_SOCKET_FUNC         BIO_NEW_SOCKET;
	BIO_FREE_FUNC               BIO_FREE;
	BIO_NEW_FP_FUNC             BIO_NEW_FP;
	SSL_SET_BIO_FUNC            SSL_SET_BIO;
	SSL_CTX_USE_PRIVATEKEY_FILE_FUNC	SSL_CTX_USE_PRIVATEKEY_FILE;
	SSL_CTX_CTRL_FUNC           SSL_CTX_CTRL;
	SSL_CTX_SET_VERIFY_DEPTH_FUNC SSL_CTX_SET_VERIFY_DEPTH;
	PEM_READ_BIO_DHPARAMS_FUNC  PEM_READ_BIO_DHPARAMS;

	BIO_F_BASE64_FUNC           BIO_F_BASE64;
#ifndef BIO_set_flags /* compatibility check with older openssl library */
	BIO_SET_FLAGS_FUNC          BIO_SET_FLAGS;
#endif
	BIO_NEW_FUNC                BIO_NEW;
	BIO_PUSH_FUNC               BIO_PUSH;
	BIO_READ_FUNC               BIO_READ;
	BIO_FREE_ALL_FUNC           BIO_FREE_ALL;
	BIO_NEW_MEM_BUF_FUNC        BIO_NEW_MEM_BUF;
	BIO_WRITE_FUNC              BIO_WRITE;
	BIO_S_MEM_FUNC              BIO_S_MEM;
	BIO_CTRL_FUNC               BIO_CTRL;
	MD2_INIT_FUNC               MD2_INIT;
	MD2_UPDATE_FUNC             MD2_UPDATE;
	MD2_FINAL_FUNC              MD2_FINAL;
	MD4_INIT_FUNC               MD4_INIT;
	MD4_UPDATE_FUNC             MD4_UPDATE;
	MD4_FINAL_FUNC              MD4_FINAL;
	MD5_INIT_FUNC               MD5_INIT;
	MD5_UPDATE_FUNC             MD5_UPDATE;
	MD5_FINAL_FUNC              MD5_FINAL;
	SHA1_INIT_FUNC              SHA1_INIT;
	SHA1_UPDATE_FUNC            SHA1_UPDATE;
	SHA1_FINAL_FUNC             SHA1_FINAL;
	SSLModule();
	~SSLModule();

};
#endif

