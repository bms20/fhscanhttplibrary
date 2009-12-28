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
#ifndef __HTTPHANDLE__
#define __HTTPHANDLE__

#include "Build.h"
#include <stdlib.h>
#include <string.h>

#define MAXIMUM_HTTP_REDIRECT_DEPTH 2

typedef int HTTPHANDLE;

enum AuthenticationType {
	NO_AUTH        = 0,
	BASIC_AUTH     = 1,
	DIGEST_AUTH    = 2,
	NTLM_AUTH      = 4,
	NEGOTIATE_AUTH = 8,
	UNKNOWN_AUTH   = 16
};

/* Options for SetHTTPConfig() and GetHTTPConfig() */
enum HttpOptions 
{  
	ConfigProxyHost        = 0x00,
	ConfigProxyPort        = 0x01,
	ConfigProxyUser        = 0x02,
	ConfigProxyPass        = 0x04,

	ConfigAdditionalHeader = 0x08,
	ConfigCookie           = 0x10,
	ConfigUserAgent        = 0x20,
	ConfigProtocolversion  = 0x40,
	ConfigMaxDownloadSpeed = 0x80,
	ConfigHTTPHost         = 0x100,
	ConfigHTTPPort         = 0x200,
	ConfigAsyncronousProxy = 0x400,
	ConfigProxyInitialized = 0x800,
	ConfigSSLConnection    = 0x1000,
	ConfigMaxDownloadSize  = 0x2000,
	ConfigCookieHandling   = 0x4000,
	ConfigAutoredirect     = 0x8000,
	ConfigDisconnectConnection = 0x10000
};

class HTTPHOST {
	long target;
	HTTPCHAR targetDNS[256];
	unsigned short port;
	int NeedSSL;
};



class HTTPAPIHANDLE {
	long 		target;
	HTTPCHAR	targetDNS[256];
	unsigned short	port;
#ifdef __WIN32__RELEASE__
	int			ThreadID;
#else
	pthread_t   ThreadID;
#endif
	int 		NeedSSL;
	int 		version;
	
	HTTPSTR		AdditionalHeader;
	HTTPSTR		Cookie;
	HTTPSTR		UserAgent;
	HTTPSTR		DownloadBwLimit;
	HTTPSTR		DownloadLimit;
	void		*conexion;			/* STABLISHED_CONNECTION *conexion; //Pointer to last used connection */
	void		*ClientConnection;  /* STABLISHED_CONNECTION *ClientConnection; //for asyncronous i/o  */
	int		    AsyncHTTPRequest;
	
	HTTPSTR		LastRequestedUri;
	HTTPSTR		LastAuthenticationString;

	HTTPSTR		lpProxyHost;
	HTTPSTR		lpProxyPort;
	HTTPSTR		lpProxyUserName;
	HTTPSTR		lpProxyPassword;
	int			ProxyInitialized;
	HTTPCHAR	lpTmpData[256]; //not thread safe struct

	int 		CookieSupported;
	int			AutoRedirect;
	int 		MaximumRedirects;

public:
	enum AuthenticationType challenge;
	int			DisconnectSocket;

	HTTPAPIHANDLE(void);	
	~HTTPAPIHANDLE();
	int InitHandle(HTTPSTR,unsigned short,int);	
	int SetHTTPConfig(int,HTTPCSTR);
	int SetHTTPConfig(int,int);
	HTTPSTR GetHTTPConfig(enum HttpOptions);

	//Authentication related
	HTTPCHAR *GetLastRequestedUri(void);
	void SetLastRequestedUri(HTTPCSTR url);
	HTTPCHAR *GetLastAuthenticationString() { return LastAuthenticationString; }
	void SetLastAuthenticationString(HTTPCHAR *authstring);

	//Connection related
	long GetTarget() { return target; }
	unsigned short GetPort() { return(port); }
	int GetThreadID() { return ThreadID; }
	

	//void *GetConnectionptr() { return conexion; }
	void SetConnection(void *connection) { conexion = connection; }	
	void *GetClientConnection() { return ClientConnection; }
	void SetClientConnection(void *Client_Connection) { ClientConnection = Client_Connection; }

	
	HTTPCHAR *GetAdditionalHeaderValue(HTTPCSTR value,int n);
	int IsAutoRedirectEnabled(void) { return ( AutoRedirect); }
	int GetMaximumRedirects(void) { return (MaximumRedirects); }
	void DecrementMaximumRedirectsCount(void) { MaximumRedirects--; }
	void ResetMaximumRedirects(void) { MaximumRedirects = MAXIMUM_HTTP_REDIRECT_DEPTH; }

};

#endif
