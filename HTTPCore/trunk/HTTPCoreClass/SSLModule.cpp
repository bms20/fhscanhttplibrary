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
#include "SSLModule.h"

int Initialized = 0;
#ifdef __WIN32__RELEASE__
#include "windows.h"
HMODULE				f_hSSLEAY32 = NULL;
HMODULE				f_hLIBEAY32 = NULL;

SSLModule::SSLModule()
{
	if ( (!f_hSSLEAY32) || (!f_hSSLEAY32) )
	{
		f_hLIBEAY32 = LoadLibraryA("libeay32.dll");
		f_hSSLEAY32 = LoadLibraryA("ssleay32.dll");
		if ( (!f_hLIBEAY32) || (!f_hSSLEAY32) )
		{
			//printf("## FATAL - SSL LIBRARIES NOT FOUND\n");
			exit(0);
		}
	}
	SSL_NEW                            = (SSL_NEW_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_new");
	SSL_FREE                           = (SSL_FREE_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_free");
	SSL_SHUTDOWN                       = (SSL_SHUTDOWN_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_shutdown");
	SSL_READ                           = (SSL_READ_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_read");
	SSL_WRITE                          = (SSL_WRITE_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_write");
	SSL_CTX_FREE                       = (SSL_CTX_FREE_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_CTX_free");
	SSL_CTX_NEW                        = (SSL_CTX_NEW_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_CTX_new");
	SSL_CONNECT                        = (SSL_CONNECT_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_connect");
	SSL_GET_ERROR                      = (SSL_GET_ERROR_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_get_error");
	SSL_SET_FD                         = (SSL_SET_FD_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_set_fd");
	SSL_PENDING                        = (SSL_PENDING_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_pending");
	TLSV1_CLIENT_METHOD                = (TLSV1_CLIENT_METHOD_FUNC)GetProcAddress(f_hSSLEAY32, "TLSv1_client_method");
	SSL_LOAD_ERROR_STRINGS             = (SSL_LOAD_ERROR_STRINGS_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_load_error_strings");
	SSL_LIBRARY_INIT                   = (SSL_LIBRARY_INIT_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_library_init");

	SSLV23_METHOD                      = (SSLV23_METHOD_FUNC)GetProcAddress(f_hSSLEAY32, "SSLv23_method");
	SSL_CTX_SET_DEFAULT_PASSWD_CB	   = (SSL_CTX_SET_DEFAULT_PASSWD_CB_FUNC) GetProcAddress(f_hSSLEAY32, "SSL_CTX_set_default_passwd_cb");
	SSL_ACCEPT						   = (SSL_ACCEPT_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_accept");
	SSL_CTX_LOAD_VERIFY_LOCATIONS      = (SSL_CTX_LOAD_VERIFY_LOCATIONS_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_CTX_load_verify_locations");
	BIO_NEW_FILE					   = (BIO_NEW_FILE_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_new_file");
	SSL_CTX_USE_CERTIFICATE_CHAIN_FILE = (SSL_CTX_USE_CERTIFICATE_CHAIN_FILE_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_CTX_use_certificate_chain_file");
	BIO_NEW_SOCKET					   = (BIO_NEW_SOCKET_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_new_socket");
	BIO_FREE							= (BIO_FREE_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_free");
	BIO_NEW_FP						  = (BIO_NEW_FP_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_new_fp");
	SSL_SET_BIO      = (SSL_SET_BIO_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_set_bio");
	SSL_CTX_USE_PRIVATEKEY_FILE      = (SSL_CTX_USE_PRIVATEKEY_FILE_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_CTX_use_PrivateKey_file");
	SSL_CTX_CTRL      = (SSL_CTX_CTRL_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_CTX_ctrl");
	SSL_CTX_SET_VERIFY_DEPTH      = (SSL_CTX_SET_VERIFY_DEPTH_FUNC)GetProcAddress(f_hSSLEAY32, "SSL_CTX_set_verify_depth");
	PEM_READ_BIO_DHPARAMS      = (PEM_READ_BIO_DHPARAMS_FUNC)GetProcAddress(f_hLIBEAY32, "PEM_read_bio_DHparams");

	BIO_F_BASE64				  = (BIO_F_BASE64_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_f_base64");
#ifndef BIO_set_flags
	BIO_SET_FLAGS				  = (BIO_SET_FLAGS_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_set_flags");
#endif
	BIO_NEW						  = (BIO_NEW_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_new");
	BIO_PUSH					  = (BIO_PUSH_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_push");
	BIO_READ					  = (BIO_READ_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_read");
	BIO_WRITE					  = (BIO_WRITE_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_write");
	BIO_FREE_ALL				  = (BIO_FREE_ALL_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_free_all");
	BIO_NEW_MEM_BUF				  = (BIO_NEW_MEM_BUF_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_new_mem_buf");
	BIO_S_MEM                     = (BIO_S_MEM_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_s_mem");
	BIO_CTRL                      = (BIO_CTRL_FUNC)GetProcAddress(f_hLIBEAY32, "BIO_ctrl");
	MD2_INIT                      = (MD2_INIT_FUNC)GetProcAddress(f_hLIBEAY32, "MD2_Init");
	MD2_UPDATE                    = (MD2_UPDATE_FUNC)GetProcAddress(f_hLIBEAY32, "MD2_Update");
	MD2_FINAL                     = (MD2_FINAL_FUNC)GetProcAddress(f_hLIBEAY32, "MD2_Final");
	MD4_INIT                      = (MD4_INIT_FUNC)GetProcAddress(f_hLIBEAY32, "MD4_Init");
	MD4_UPDATE                    = (MD4_UPDATE_FUNC)GetProcAddress(f_hLIBEAY32, "MD4_Update");
	MD4_FINAL                     = (MD4_FINAL_FUNC)GetProcAddress(f_hLIBEAY32, "MD4_Final");
	MD5_INIT                      = (MD5_INIT_FUNC)GetProcAddress(f_hLIBEAY32, "MD5_Init");
	MD5_UPDATE                    = (MD5_UPDATE_FUNC)GetProcAddress(f_hLIBEAY32, "MD5_Update");
	MD5_FINAL                     = (MD5_FINAL_FUNC)GetProcAddress(f_hLIBEAY32, "MD5_Final");
	SHA1_INIT                     = (SHA1_INIT_FUNC)GetProcAddress(f_hLIBEAY32, "SHA1_Init");
	SHA1_UPDATE                   = (SHA1_UPDATE_FUNC)GetProcAddress(f_hLIBEAY32, "SHA1_Update");
	SHA1_FINAL                    = (SHA1_FINAL_FUNC)GetProcAddress(f_hLIBEAY32, "SHA1_Final");
	if (!SSL_NEW || !SSL_FREE || !SSL_SHUTDOWN || !SSL_READ || !SSL_WRITE || !SSL_CTX_FREE || !SSL_CTX_NEW || !SSL_CONNECT || !SSL_GET_ERROR || !SSL_SET_FD || !SSL_PENDING || !TLSV1_CLIENT_METHOD || !SSL_LOAD_ERROR_STRINGS || !SSL_LIBRARY_INIT)
	{
		//printf("#FATAL SSL LIBS\n");
		exit(0);
	}
	if (!Initialized)
	{
		Initialized = 1;
		SSL_LOAD_ERROR_STRINGS();
		SSL_LIBRARY_INIT();
	}
}
#else
SSLModule::SSLModule()
{
	SSL_NEW= (SSL_NEW_FUNC)SSL_new;
	SSL_FREE                           = (SSL_FREE_FUNC)SSL_free;
	SSL_SHUTDOWN                       = (SSL_SHUTDOWN_FUNC)SSL_shutdown;
	SSL_READ                           = (SSL_READ_FUNC)SSL_read;
	SSL_WRITE                          = (SSL_WRITE_FUNC)SSL_write;
	SSL_CTX_FREE                       = (SSL_CTX_FREE_FUNC)SSL_CTX_free;
	SSL_CTX_NEW                        = (SSL_CTX_NEW_FUNC)SSL_CTX_new;
	SSL_CONNECT                        = (SSL_CONNECT_FUNC)SSL_connect;
	SSL_GET_ERROR                      = (SSL_GET_ERROR_FUNC)SSL_get_error;
	SSL_SET_FD                         = (SSL_SET_FD_FUNC)SSL_set_fd;
	SSL_PENDING                        = (SSL_PENDING_FUNC)SSL_pending;
	TLSV1_CLIENT_METHOD                = (TLSV1_CLIENT_METHOD_FUNC)TLSv1_client_method;
	SSL_LOAD_ERROR_STRINGS             = (SSL_LOAD_ERROR_STRINGS_FUNC)SSL_load_error_strings;
	SSL_LIBRARY_INIT                   = (SSL_LIBRARY_INIT_FUNC)SSL_library_init;

	SSLV23_METHOD                      = (SSLV23_METHOD_FUNC)SSLv23_method;
	SSL_CTX_SET_DEFAULT_PASSWD_CB	   = (SSL_CTX_SET_DEFAULT_PASSWD_CB_FUNC) SSL_CTX_set_default_passwd_cb;
	SSL_ACCEPT						   = (SSL_ACCEPT_FUNC)SSL_accept;
	SSL_CTX_LOAD_VERIFY_LOCATIONS      = (SSL_CTX_LOAD_VERIFY_LOCATIONS_FUNC)SSL_CTX_load_verify_locations;
	BIO_NEW_FILE					   = (BIO_NEW_FILE_FUNC)BIO_new_file;
	SSL_CTX_USE_CERTIFICATE_CHAIN_FILE = (SSL_CTX_USE_CERTIFICATE_CHAIN_FILE_FUNC)SSL_CTX_use_certificate_chain_file;
	BIO_NEW_SOCKET					   = (BIO_NEW_SOCKET_FUNC)BIO_new_socket;
	BIO_FREE							= (BIO_FREE_FUNC)BIO_free;
	BIO_NEW_FP						  = (BIO_NEW_FP_FUNC)BIO_new_fp;
	SSL_SET_BIO      = (SSL_SET_BIO_FUNC)SSL_set_bio;
	SSL_CTX_USE_PRIVATEKEY_FILE      = (SSL_CTX_USE_PRIVATEKEY_FILE_FUNC)SSL_CTX_use_PrivateKey_file;
	SSL_CTX_CTRL      = (SSL_CTX_CTRL_FUNC)SSL_CTX_ctrl;
	SSL_CTX_SET_VERIFY_DEPTH      = (SSL_CTX_SET_VERIFY_DEPTH_FUNC)SSL_CTX_set_verify_depth;
	PEM_READ_BIO_DHPARAMS      = (PEM_READ_BIO_DHPARAMS_FUNC)PEM_read_bio_DHparams;

	BIO_F_BASE64				  = (BIO_F_BASE64_FUNC)BIO_f_base64;
#ifndef (BIO_set_flags)
	BIO_SET_FLAGS				  = (BIO_SET_FLAGS_FUNC)BIO_set_flags;
#endif
	BIO_NEW						  = (BIO_NEW_FUNC)BIO_new;
	BIO_PUSH					  = (BIO_PUSH_FUNC)BIO_push;
	BIO_READ					  = (BIO_READ_FUNC)BIO_read;
	BIO_WRITE					  = (BIO_WRITE_FUNC)BIO_write;
	BIO_FREE_ALL				  = (BIO_FREE_ALL_FUNC)BIO_free_all;
	BIO_NEW_MEM_BUF				  = (BIO_NEW_MEM_BUF_FUNC)BIO_new_mem_buf;
	BIO_S_MEM                     = (BIO_S_MEM_FUNC)BIO_s_mem;
	BIO_CTRL                      = (BIO_CTRL_FUNC)BIO_ctrl;
	MD2_INIT                      = (MD2_INIT_FUNC)MD2_Init;
	MD2_UPDATE                    = (MD2_UPDATE_FUNC)MD2_Update;
	MD2_FINAL                     = (MD2_FINAL_FUNC)MD2_Final;
	MD4_INIT                      = (MD4_INIT_FUNC)MD4_Init;
	MD4_UPDATE                    = (MD4_UPDATE_FUNC)MD4_Update;
	MD4_FINAL                     = (MD4_FINAL_FUNC)MD4_Final;
	MD5_INIT                      = (MD5_INIT_FUNC)MD5_Init;
	MD5_UPDATE                    = (MD5_UPDATE_FUNC)MD5_Update;
	MD5_FINAL                     = (MD5_FINAL_FUNC)MD5_Final;
	SHA1_INIT                     = (SHA1_INIT_FUNC)SHA1_Init;
	SHA1_UPDATE                   = (SHA1_UPDATE_FUNC)SHA1_Update;
	SHA1_FINAL                    = (SHA1_FINAL_FUNC)SHA1_Final;
	if (!Initialized)
	{
		Initialized = 1;
		SSL_LOAD_ERROR_STRINGS();
		SSL_LIBRARY_INIT();
	}
}

#endif
SSLModule::~SSLModule()
{

}
