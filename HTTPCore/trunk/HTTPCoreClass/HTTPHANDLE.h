#ifndef __HTTPHANDLE__
#define __HTTPHANDLE__

#include "Build.h"
#include <stdlib.h>
#include <string.h>

#define MAXIMUM_HTTP_REDIRECT_DEPTH 2

enum AuthenticationType {
	NO_AUTH        = 0,
	BASIC_AUTH     = 1,
	DIGEST_AUTH    = 2,
	NTLM_AUTH      = 4,
	NEGOTIATE_AUTH = 8,
	UNKNOWN_AUTH   = 16
};

class HTTPAPIHANDLE {
	long 		target;
	HTTPCHAR	targetDNS[256];
	int  		port;
#ifdef __WIN32__RELEASE__
	int			ThreadID;
#else
	pthread_t   ThreadID;
#endif
	#ifdef _OPENSSL_SUPPORT_
	int 		NeedSSL;
	#endif
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
	HTTPCHAR	lpTmpData[256]; //not thread safe struct

	int 		CookieSupported;
	int			AutoRedirect;
	int 		MaximumRedirects;
public:
	enum AuthenticationType challenge;

//Definir como metodos restringidos a CONEXION!
	long GetTarget() { return target; }
	int GetPort() { return(port); }
	int IsSSLNeeded() 
	{ 		
		#ifdef _OPENSSL_SUPPORT_
			return NeedSSL; 
		#else
			return 0;
		#endif
	}
	int ProxyEnabled() { return (lpProxyHost != NULL);}
	int GetDownloadBwLimit() { if (DownloadBwLimit) return atoi(DownloadBwLimit); else return(0); }
	int GetDownloadLimit() { if (DownloadLimit) return (atoi(DownloadLimit)); else return(0); }
	int GetThreadID() { return ThreadID; }
	HTTPSTR GettargetDNS() { return targetDNS; }
	int GetVersion() { return version; }
	HTTPSTR GetUserAgent() { return ( UserAgent); }
	HTTPSTR GetAdditionalHeader() { return (AdditionalHeader); }
	HTTPSTR GetCookie() { return Cookie; }
	HTTPSTR GetlpProxyUserName() { return (lpProxyUserName); }
	HTTPSTR	GetlpProxyPassword() { return (lpProxyPassword); }
	

	char *GetLastRequestedUri() { return LastRequestedUri; };
	void SetLastRequestedUri(const char *url)
	{
		if (LastRequestedUri) free(LastRequestedUri);
		if (url)
		{
			LastRequestedUri = strdup(url);
		} else
		{
         	LastRequestedUri = NULL;
        }

    }

	char *GetLastAuthenticationString() { return LastAuthenticationString; }
	void SetLastAuthenticationString(char *authstring) {
		if (LastAuthenticationString) free(LastAuthenticationString);
		LastAuthenticationString = authstring;
	}
	void *ParseReturnedBuffer(struct httpdata *request, struct httpdata *response);
	

	//Connection links
	void *GetConnection() { return conexion; }
	void SetConnection(void *connection) { conexion = connection; }	
	void *GetClientConnection() { return ClientConnection; }
	void SetClientConnection(void *Client_Connection) { ClientConnection = Client_Connection; }

	HTTPAPIHANDLE(void);	
	~HTTPAPIHANDLE();
	int InitHandle(HTTPSTR,int,int);	
	int SetHTTPConfig(int,HTTPCSTR);
	int SetHTTPConfig(int,int);
	HTTPSTR GetHTTPConfig(int);
	char *GetAdditionalHeaderValue(const char *value,int n);
	int IsCookieSupported(void) { return CookieSupported; }
	int IsAutoRedirectEnabled(void) { return ( AutoRedirect); }

	int GetMaximumRedirects(void) { return (MaximumRedirects); }
	void DecrementMaximumRedirectsCount(void) { MaximumRedirects--; }
	void ResetMaximumRedirects(void) { MaximumRedirects = MAXIMUM_HTTP_REDIRECT_DEPTH; }



};

#endif