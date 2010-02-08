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
/** \file HTTP.h
 * Fast HTTP Auth Scanner - HTTP Engine v1.4.
 * This include file contains all needed information to manage the HTTP interface from the user side.
 * \author Andres Tarasco Acuna - http://www.tarasco.org
 */
#ifndef __HTTPAPI__
#define __HTTPAPI__

//#include "HTTPHANDLE.h"
//#include "HTTPData.h"
//#include "HTTPResponse.h"
#include "Build.h"
#include "HTTPSession.h"
#include "Threading.h"
#include "CallBacks.h"
//#include "SSLModule.h"
#include "encoders.h"


/* Options for SetHTTPProxyConfig() */
enum HttpProxyoptions 
{  
	ProxyAllowConnect      = 0x00,
	ProxyAnonymous         = 0x01,
	ProxyAsynRequest       = 0x02,
	ProxyDisableCache      = 0x03,
	ProxyOriginalUserAgent = 0x04,
	ProxyDefaultPorts      = 0x05
};

/* CancelHTTPRequest() options */
//#define HTTP_REQUEST_CURRENT 1
//#define HTTP_REQUEST_ALL	 0

/* Important Handle values */
#define	INVALID_HHTPHANDLE_VALUE ((HTTPHANDLE)-1)
#define	GLOBAL_HTTP_CONFIG       ((HTTPHANDLE)-2)


#define MAXIMUM_OPENED_HANDLES	 4096
#define MAX_OPEN_CONNECTIONS     1024 /* Our Connection table is able to handle 1024 concurrent connections */




/***********************************************************************************************/
class HTTPAPI : public encoders
{
	
	class HTTPAPIHANDLE GlobalHTTPCoreApiOptions;/*Global HANDLE Configuration Options */	
	class HTTPAPIHANDLE *HTTPHandleTable[MAXIMUM_OPENED_HANDLES];/*HTTP Handle table*/	
	class ConnectionHandling *Connection_Table[MAX_OPEN_CONNECTIONS];/*Connection table (conexiones concurrentes) */	
	class HTTPCALLBACK HTTPCallBack;	/* CallBacks */
	class Threading HandleLock;			/* internal Threads */
	class Threading ConnectionTablelock;/* internal Mutex for handling Connection table modifications*/
	class Threading ProxyEngine;		/* internal Threads */
	#ifdef __WIN32__RELEASE__
	WSADATA ws;							/* Win32 Sockets */
	#endif

	HTTPCHAR BindIpAdress[256];			/* Proxy Bind Address */
	unsigned short BindPort;			/* Proxy Bind Port */
	SOCKET ListenSocket;				/* Listen proxy socket */
	int ForceDefaultHTTPPorts;			/* Proxy configuration option */
	int AnonymousProxy;					/* Proxy configuration option */
	int AsyncHTTPRequest;				/* Proxy configuration option */
	int DisableBrowserCache ;			/* Proxy configuration option */
	int ConnectMethodAllowed;			/* Proxy configuration option */
	int UseOriginalUserAgent;			/* Proxy configuration option */
	void *ctx;							/* Proxy SSL vars */
	void *bio_err;						/* Proxy SSL vars */
	int InitProxyCTX(void);
	HTTPCHAR	*FHScanUserAgent;			/* HTTPAPI User Agent */
	class CookieStatus *COOKIE;         /* Automatic Cookie Handling struct */
	
	friend int ThreadFunc(void *foo);
	friend int ListenConnectionThreadFunc(void *foo);
	friend int DispatchHTTPProxyRequestThreadFunc(void *foo);
	
	class HTTPAPIHANDLE *GetHTTPAPIHANDLE(HTTPHANDLE HTTPHandle);	
	void  CleanConnectionTable(LPVOID *unused);
	class ConnectionHandling *GetSocketConnection(class HTTPAPIHANDLE *HTTPHandle, HTTPRequest* request);
	void  BuildBasicAuthHeader(HTTPCSTR Header,HTTPCSTR lpUsername, HTTPCSTR lpPassword,HTTPSTR destination, int dstsize);
	HTTPResponse* DispatchHTTPRequest(HTTPHANDLE HTTPHandle, HTTPRequest* request);
	HTTPResponse* BuildHTTPProxyResponseHeader( int isSSLStablished,int closeconnection, int status, HTTPCSTR protocol,const HTTPCHAR* title, const HTTPCHAR* extra_header, const HTTPCHAR* mime_type, int length, time_t mod );
	HTTPRequest* BuildHTTPProxyTunnelConnection( HTTPHANDLE HTTPHandle);
	int   ParseRequest(HTTPSTR line, HTTPSTR method,  HTTPSTR host, HTTPSTR path, int *port);
	int   SkipHeader(HTTPSTR header);
	void  *ListenConnection(void *foo);
	int   DispatchHTTPProxyRequest(void *ListeningConnection);
	void  SendHTTPProxyErrorMessage( ConnectionHandling* connection,int connectionclose, int status,HTTPCSTR protocol, HTTPCSTR title, HTTPCSTR extra_header, HTTPCSTR text );
	void  ExtractCookiesFromResponseData( HTTPResponse* response, HTTPCSTR path, HTTPCSTR TargetDNS);
	HTTPCHAR  *BuildCookiesFromStoredData( HTTPCSTR TargetDNS, HTTPCSTR path, int secure);
	HTTPRequest* BuildHTTPRequest(HTTPHANDLE HTTPHandle,HTTPCSTR VHost,HTTPCSTR HTTPMethod,HTTPCSTR url,HTTPSTR PostData,size_t PostDataSize);
	HTTPCHAR  *GetPathFromURL(HTTPCSTR url);
	HTTPCHAR  *GetPathFromLocationHeader(HTTPResponse* response, int ssl, const HTTPCHAR* domain);
	enum AuthenticationType GetSupportedAuthentication(HTTPResponse *response);
	
public:
	HTTPAPI();
	~HTTPAPI();

	HTTPHANDLE InitHTTPConnectionHandle(HTTPSTR lpHostName, int port);
	HTTPHANDLE InitHTTPConnectionHandle(HTTPSTR lpHostName, int port, int ssl);	
	int        EndHTTPConnectionHandle(HTTPHANDLE);

	int        SetHTTPConfig(HTTPHANDLE HTTPHandle, enum HttpOptions opt, HTTPCSTR parameter);
	int        SetHTTPConfig(HTTPHANDLE HTTPHandle, enum HttpOptions opt, int parameter);
	HTTPSTR    GetHTTPConfig(HTTPHANDLE HTTPHandle, enum HttpOptions opt);
		
	HTTPSession*   SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPCSTR HTTPMethod,HTTPCSTR lpPath);
	HTTPSession*   SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPCSTR HTTPMethod,HTTPCSTR lpPath,HTTPSTR PostData);	
	HTTPSession*   SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPCSTR HTTPMethod,HTTPCSTR lpPath,HTTPSTR PostData,HTTPCSTR lpUsername,HTTPCSTR lpPassword);
	HTTPSession*   SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPCSTR VHost,HTTPCSTR HTTPMethod,HTTPCSTR lpPath,HTTPSTR PostData,size_t PostDataSize,HTTPCSTR lpUsername,HTTPCSTR lpPassword);
	HTTPSession*   SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPRequest* request);
	HTTPSession*   SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPRequest* request,HTTPCSTR lpUsername,HTTPCSTR lpPassword);
	HTTPSession*   SendHttpRequest(HTTPCSTR Fullurl);
	
	HTTPSession*   SendRawHTTPRequest(HTTPHANDLE HTTPHandle,HTTPCSTR headers, HTTPSTR PostData, size_t PostDataSize);

	int        InitHTTPProxy(HTTPCSTR hostname, unsigned short port);
	int        InitHTTPProxy(HTTPCSTR hostname, HTTPCSTR port);
	void       SetHTTPProxyConfig(enum HttpProxyoptions opt,HTTPSTR parameter);
	void       SetHTTPProxyConfig(enum HttpProxyoptions opt,int parameter);
	int        StopHTTPProxy();

	int        RegisterHTTPCallBack(unsigned int cbType, HTTP_IO_REQUEST_CALLBACK cb,HTTPCSTR Description);
	void       CancelHTTPRequest(HTTPHANDLE HTTPHandle);
#ifdef _SPIDER_
	void       doSpider(HTTPSTR host,HTTPSTR FullPath, HTTPResponse*  response);
#endif
};	


#ifndef __AFXISAPI_H_ // these symbols may come from WININET.H
//! OK to continue with request
#define HTTP_STATUS_CONTINUE            100
//! server has switched protocols in upgrade header
#define HTTP_STATUS_SWITCH_PROTOCOLS    101
//! request completed
#define HTTP_STATUS_OK                  200
//! object created, reason = new URI
#define HTTP_STATUS_CREATED             201
//! async completion (TBS)
#define HTTP_STATUS_ACCEPTED            202
//! partial completion
#define HTTP_STATUS_PARTIAL             203
//! no info to return
#define HTTP_STATUS_NO_CONTENT          204
//! request completed, but clear form
#define HTTP_STATUS_RESET_CONTENT       205
//! partial GET furfilled
#define HTTP_STATUS_PARTIAL_CONTENT     206
//! server couldn't decide what to return
#define HTTP_STATUS_AMBIGUOUS           300
//! object permanently moved
#define HTTP_STATUS_MOVED               301
//! object temporarily moved
#define HTTP_STATUS_REDIRECT            302
//! redirection w/ new access method
#define HTTP_STATUS_REDIRECT_METHOD     303
//! if-modified-since was not modified
#define HTTP_STATUS_NOT_MODIFIED        304
//! redirection to proxy, location header specifies proxy to use
#define HTTP_STATUS_USE_PROXY           305
//! HTTP/1.1: keep same verb
#define HTTP_STATUS_REDIRECT_KEEP_VERB  307
//! invalid syntax
#define HTTP_STATUS_BAD_REQUEST         400
//! access denied
#define HTTP_STATUS_DENIED              401
//! payment required
#define HTTP_STATUS_PAYMENT_REQ         402
//! request forbidden
#define HTTP_STATUS_FORBIDDEN           403
//! object not found
#define HTTP_STATUS_NOT_FOUND           404
//! method is not allowed
#define HTTP_STATUS_BAD_METHOD          405
//! no response acceptable to client found
#define HTTP_STATUS_NONE_ACCEPTABLE     406
//! proxy authentication required
#define HTTP_STATUS_PROXY_AUTH_REQ      407
//! server timed out waiting for request
#define HTTP_STATUS_REQUEST_TIMEOUT     408
//! user should resubmit with more info
#define HTTP_STATUS_CONFLICT            409
//! the resource is no longer available
#define HTTP_STATUS_GONE                410
//! the server refused to accept request w/o a length
#define HTTP_STATUS_LENGTH_REQUIRED     411
//! precondition given in request failed
#define HTTP_STATUS_PRECOND_FAILED      412
//! request entity was too large
#define HTTP_STATUS_REQUEST_TOO_LARGE   413
//! request URI too long
#define HTTP_STATUS_URI_TOO_LONG        414
//! unsupported media type
#define HTTP_STATUS_UNSUPPORTED_MEDIA   415
//! internal server error
#define HTTP_STATUS_SERVER_ERROR        500
//! required not supported
#define HTTP_STATUS_NOT_SUPPORTED       501
//! error response received from gateway
#define HTTP_STATUS_BAD_GATEWAY         502
//! temporarily overloaded
#define HTTP_STATUS_SERVICE_UNAVAIL     503
//! timed out waiting for gateway
#define HTTP_STATUS_GATEWAY_TIMEOUT     504
//! HTTP version not supported
#define HTTP_STATUS_VERSION_NOT_SUP     505
#endif

#endif
