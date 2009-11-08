#ifndef _SSLMODULE_H_
#define _SSLMODULE_H_
#ifdef _OPENSSL_SUPPORT_
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

 #ifdef __WIN32__RELEASE__
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

	extern SSL_NEW_FUNC                SSL_NEW;
	extern SSL_FREE_FUNC               SSL_FREE;
	extern SSL_SHUTDOWN_FUNC           SSL_SHUTDOWN;
	extern SSL_READ_FUNC               SSL_READ;
	extern SSL_WRITE_FUNC              SSL_WRITE;
	extern SSL_CTX_FREE_FUNC           SSL_CTX_FREE;
	extern SSL_CTX_NEW_FUNC            SSL_CTX_NEW;
	extern SSL_CONNECT_FUNC            SSL_CONNECT;
	extern SSL_GET_ERROR_FUNC		   SSL_GET_ERROR;
	extern SSL_SET_FD_FUNC             SSL_SET_FD;
	extern SSL_PENDING_FUNC			   SSL_PENDING;
	extern TLSV1_CLIENT_METHOD_FUNC    TLSV1_CLIENT_METHOD;
	extern SSL_LOAD_ERROR_STRINGS_FUNC SSL_LOAD_ERROR_STRINGS;
	extern SSL_LIBRARY_INIT_FUNC	   SSL_LIBRARY_INIT;

	extern SSLV23_METHOD_FUNC		   SSLV23_METHOD;
	extern SSL_CTX_SET_DEFAULT_PASSWD_CB_FUNC	SSL_CTX_SET_DEFAULT_PASSWD_CB;
	extern SSL_ACCEPT_FUNC				SSL_ACCEPT;
	extern SSL_CTX_LOAD_VERIFY_LOCATIONS_FUNC	SSL_CTX_LOAD_VERIFY_LOCATIONS;
	extern BIO_NEW_FILE_FUNC			BIO_NEW_FILE;
	extern SSL_CTX_USE_CERTIFICATE_CHAIN_FILE_FUNC	SSL_CTX_USE_CERTIFICATE_CHAIN_FILE;
	extern BIO_NEW_SOCKET_FUNC			BIO_NEW_SOCKET;
	extern BIO_FREE_FUNC				BIO_FREE;
	extern BIO_NEW_FP_FUNC				BIO_NEW_FP;
	extern SSL_SET_BIO_FUNC					SSL_SET_BIO;
	extern SSL_CTX_USE_PRIVATEKEY_FILE_FUNC	SSL_CTX_USE_PRIVATEKEY_FILE;
	extern SSL_CTX_CTRL_FUNC	SSL_CTX_CTRL;
	extern SSL_CTX_SET_VERIFY_DEPTH_FUNC SSL_CTX_SET_VERIFY_DEPTH;
	extern PEM_READ_BIO_DHPARAMS_FUNC		PEM_READ_BIO_DHPARAMS;

	typedef BIO_METHOD*   (*BIO_F_BASE64_FUNC)(void);
	extern			BIO_F_BASE64_FUNC BIO_F_BASE64;

	typedef int   (*BIO_SET_FLAGS_FUNC)(BIO*,int);
	extern          BIO_SET_FLAGS_FUNC BIO_SET_FLAGS;

	typedef BIO*  (*BIO_NEW_FUNC)(BIO_METHOD *);
	extern			BIO_NEW_FUNC BIO_NEW;

	typedef int   (*BIO_WRITE_FUNC)(BIO*,const void*, int);
	extern			BIO_WRITE_FUNC BIO_WRITE;

	typedef BIO*  (*BIO_PUSH_FUNC)(BIO*,BIO*);
	extern			BIO_PUSH_FUNC BIO_PUSH;

	typedef int (*BIO_READ_FUNC)(BIO*,void*,int);
	extern			BIO_READ_FUNC BIO_READ;

	typedef BIO*	(*BIO_NEW_MEM_BUF_FUNC) (void*,int);
	extern			BIO_NEW_MEM_BUF_FUNC BIO_NEW_MEM_BUF;

	typedef void  (*BIO_FREE_ALL_FUNC)(BIO*);
	extern			BIO_FREE_ALL_FUNC BIO_FREE_ALL;

	typedef BIO_METHOD* (*BIO_S_MEM_FUNC)();
	extern BIO_S_MEM_FUNC BIO_S_MEM;

	typedef long (*BIO_CTRL_FUNC)(BIO*,int,long,void*);
	extern BIO_CTRL_FUNC BIO_CTRL;

	typedef int (*MD2_INIT_FUNC)(MD2_CTX*);
	extern MD2_INIT_FUNC MD2_INIT;

	typedef int (*MD2_UPDATE_FUNC)(MD2_CTX*,const void*, unsigned long);
	extern MD2_UPDATE_FUNC MD2_UPDATE;

	typedef int (*MD2_FINAL_FUNC)(unsigned char*, MD2_CTX*);
	extern MD2_FINAL_FUNC MD2_FINAL;

	typedef int (*MD4_INIT_FUNC)(MD4_CTX*);
	extern MD4_INIT_FUNC MD4_INIT;

	typedef int (*MD4_UPDATE_FUNC)(MD4_CTX*,const void*, unsigned long);
	extern MD4_UPDATE_FUNC MD4_UPDATE;

	typedef int (*MD4_FINAL_FUNC)(unsigned char*, MD4_CTX*);
	extern MD4_FINAL_FUNC MD4_FINAL;

	typedef int (*MD5_INIT_FUNC)(MD5_CTX*);
	extern MD5_INIT_FUNC MD5_INIT;

	typedef int (*MD5_UPDATE_FUNC)(MD5_CTX*,const void*, unsigned long);
	extern MD5_UPDATE_FUNC MD5_UPDATE;

	typedef int (*MD5_FINAL_FUNC)(unsigned char*, MD5_CTX*);
	extern MD5_FINAL_FUNC MD5_FINAL;

	typedef int (*SHA1_INIT_FUNC)(SHA_CTX*);
	extern SHA1_INIT_FUNC SHA1_INIT;

	typedef int (*SHA1_UPDATE_FUNC)(SHA_CTX*,const void*, unsigned long);
	extern SHA1_UPDATE_FUNC SHA1_UPDATE;

	typedef int (*SHA1_FINAL_FUNC)(unsigned char*, SHA_CTX*);
	extern SHA1_FINAL_FUNC SHA1_FINAL;
	#else
	#define SSL_NEW SSL_new
	#define SSL_FREE SSL_free
	#define SSL_SHUTDOWN SSL_shutdown
	#define SSL_READ SSL_read
	#define SSL_WRITE SSL_write
	#define SSL_CTX_FREE SSL_CTX_free
	#define SSL_CTX_NEW SSL_CTX_new
	#define SSL_CONNECT SSL_connect
	#define SSL_GET_ERROR SSL_get_error
	#define SSL_SET_FD SSL_set_fd
	#define SSL_PENDING SSL_pending
	#define TLSV1_CLIENT_METHOD TLSv1_client_method
	#define SSL_LOAD_ERROR_STRINGS SSL_load_error_strings
	#define SSL_LIBRARY_INIT SSL_library_init

	#define SSLV23_METHOD	SSLv23_method
	#define SSL_CTX_SET_DEFAULT_PASSWD_CB SSL_CTX_set_default_passwd_cb
	#define SSL_ACCEPT		SSL_accept
	#define SSL_CTX_LOAD_VERIFY_LOCATIONS SSL_CTX_load_verify_locations
	#define BIO_NEW_FILE			BIO_new_file
	#define SSL_CTX_USE_CERTIFICATE_CHAIN_FILE SSL_CTX_use_certificate_chain_file
	#define BIO_NEW_SOCKET BIO_new_socket
	#define BIO_FREE BIO_free
	#define BIO_NEW_FP BIO_new_fp
	#define SSL_SET_BIO	SSL_set_bio
	#define SSL_CTX_USE_PRIVATEKEY_FILE SSL_CTX_use_PrivateKey_file
	#define SSL_CTX_CTRL SSL_CTX_ctrl
	#define SSL_CTX_SET_VERIFY_DEPTH SSL_CTX_set_verify_depth
	#define PEM_READ_BIO_DHPARAMS		PEM_read_bio_DHparams;

	#define BIO_F_BASE64_FUNC 		BIO_f_base64
	#define BIO_SET_FLAGS 			BIO_set_flags
	#define BIO_NEW 				BIO_new
	#define BIO_WRITE 				BIO_write
	#define BIO_READ				BIO_read
	#define BIO_PUSH				BIO_push
	#define BIO_NEW_MEM_BUF			BIO_new_mem_buf
	#define BIO_FREE_ALL			BIO_free_all
	#define BIO_S_MEM 				BIO_s_mem
	#define BIO_CTRL				BIO_ctrl
	#define MD2_INIT				MD2_Init
	#define MD2_UPDATE				MD2_Update
	#define MD2_FINAL				MD2_Final
	#define MD4_INIT				MD4_Init
	#define MD4_UPDATE				MD4_Update
	#define MD4_FINAL				MD4_Final
	#define MD5_INIT				MD5_Init
	#define MD5_UPDATE				MD5_Update
	#define MD5_FINAL				MD5_Final
	#define SHA1_INIT				SHA1_Init
	#define SHA1_UPDATE				SHA1_Update
	#define SHA1_FINAL				SHA1_Final
	#endif


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
SSL_GET_ERROR_FUNC		    SSL_GET_ERROR;
SSL_SET_FD_FUNC             SSL_SET_FD;
SSL_PENDING_FUNC			SSL_PENDING;
TLSV1_CLIENT_METHOD_FUNC    TLSV1_CLIENT_METHOD;
SSL_LOAD_ERROR_STRINGS_FUNC SSL_LOAD_ERROR_STRINGS;
SSL_LIBRARY_INIT_FUNC		SSL_LIBRARY_INIT;

SSLV23_METHOD_FUNC		    SSLV23_METHOD;
SSL_CTX_SET_DEFAULT_PASSWD_CB_FUNC SSL_CTX_SET_DEFAULT_PASSWD_CB;
SSL_ACCEPT_FUNC				SSL_ACCEPT;
SSL_CTX_LOAD_VERIFY_LOCATIONS_FUNC SSL_CTX_LOAD_VERIFY_LOCATIONS;
BIO_NEW_FILE_FUNC			BIO_NEW_FILE;
SSL_CTX_USE_CERTIFICATE_CHAIN_FILE_FUNC	SSL_CTX_USE_CERTIFICATE_CHAIN_FILE;
BIO_NEW_SOCKET_FUNC			BIO_NEW_SOCKET;
BIO_FREE_FUNC				BIO_FREE;
BIO_NEW_FP_FUNC				BIO_NEW_FP;
SSL_SET_BIO_FUNC			SSL_SET_BIO;
SSL_CTX_USE_PRIVATEKEY_FILE_FUNC	SSL_CTX_USE_PRIVATEKEY_FILE;
SSL_CTX_CTRL_FUNC	SSL_CTX_CTRL;
SSL_CTX_SET_VERIFY_DEPTH_FUNC SSL_CTX_SET_VERIFY_DEPTH;
PEM_READ_BIO_DHPARAMS_FUNC PEM_READ_BIO_DHPARAMS;

	BIO_F_BASE64_FUNC			BIO_F_BASE64;
	BIO_SET_FLAGS_FUNC 			BIO_SET_FLAGS;
	BIO_NEW_FUNC				BIO_NEW;
	BIO_PUSH_FUNC				BIO_PUSH;
	BIO_READ_FUNC				BIO_READ;
	BIO_FREE_ALL_FUNC			BIO_FREE_ALL;
	BIO_NEW_MEM_BUF_FUNC		BIO_NEW_MEM_BUF;

	BIO_WRITE_FUNC				BIO_WRITE;
	BIO_S_MEM_FUNC 				BIO_S_MEM;
	BIO_CTRL_FUNC 				BIO_CTRL;

	MD2_INIT_FUNC 				MD2_INIT;
	MD2_UPDATE_FUNC 			MD2_UPDATE;
	MD2_FINAL_FUNC 				MD2_FINAL;

	MD4_INIT_FUNC 				MD4_INIT;
	MD4_UPDATE_FUNC 			MD4_UPDATE;
	MD4_FINAL_FUNC 				MD4_FINAL;
	MD5_INIT_FUNC 				MD5_INIT;
	MD5_UPDATE_FUNC 			MD5_UPDATE;
	MD5_FINAL_FUNC 				MD5_FINAL;
	SHA1_INIT_FUNC 				SHA1_INIT;
	SHA1_UPDATE_FUNC 			SHA1_UPDATE;
	SHA1_FINAL_FUNC 			SHA1_FINAL;
	SSLModule::SSLModule();
	SSLModule::~SSLModule();



};

#endif
#endif
