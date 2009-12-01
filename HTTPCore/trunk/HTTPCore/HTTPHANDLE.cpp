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
#include <stdio.h>
#include <stdlib.h>

#include "HTTPHANDLE.h"
#include "HTTP.h"


#ifdef __WIN32__RELEASE__
 #include <sys/timeb.h>
 #include <process.h>
 #include <time.h>
#include <windows.h>


#else
 #include <stdlib.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <sys/socket.h>
 #include <sys/ioctl.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <pthread.h>
 #include <ctype.h>
 #include <time.h>
 #include <sys/timeb.h>
 #define FILETIME time_t
#endif

/*******************************************************************************************************/
HTTPAPIHANDLE::HTTPAPIHANDLE(void)
{
	target = 0;
	*targetDNS = 0;
	port = 0;
	ThreadID = 0;
	NeedSSL = 0;
	version=0;
	AdditionalHeader = NULL;
	Cookie = NULL;
	UserAgent= NULL;
	DownloadBwLimit = NULL;
	DownloadLimit = NULL;
	conexion = NULL;
	ClientConnection = NULL;
	AsyncHTTPRequest = 0;
	LastRequestedUri = NULL;
	LastAuthenticationString = NULL;
	lpProxyHost = NULL;
	lpProxyPort = NULL;
	lpProxyUserName  = NULL;
	lpProxyPassword = NULL;
	ProxyInitialized = 0;
	memset(lpTmpData,0,sizeof(lpTmpData));

	challenge = NO_AUTH;
	CookieSupported  = 1; /* Enabled by default */
	AutoRedirect	 = 1;
	MaximumRedirects = MAXIMUM_HTTP_REDIRECT_DEPTH;

}
/*******************************************************************************************************/

int HTTPAPIHANDLE::InitHandle(HTTPSTR hostname,unsigned short HTTPPort,int ssl)
{
	struct sockaddr_in remote;
	remote.sin_addr.s_addr = inet_addr(hostname);
	if (remote.sin_addr.s_addr == INADDR_NONE)
	{
		struct hostent *hostend=gethostbyname(hostname);
		if (!hostend)
		{
			return(0);
		}
		memcpy(&remote.sin_addr.s_addr, hostend->h_addr, 4);
	}
	target=remote.sin_addr.s_addr;
	strncpy(targetDNS, hostname ,sizeof(targetDNS)-1);
	targetDNS[sizeof(targetDNS)-1]='\0';
	port			= HTTPPort;

	NeedSSL			= ssl;
	version			= 1;
	#ifdef __WIN32__RELEASE__
	ThreadID = GetCurrentThreadId();
	#else
	ThreadID = pthread_self();
	#endif

	AdditionalHeader = NULL;
	Cookie = NULL;
	UserAgent= NULL;
	DownloadBwLimit = NULL;
	DownloadLimit = NULL;
	conexion = NULL;
	ClientConnection = NULL;
	AsyncHTTPRequest = 0;
	LastRequestedUri = NULL;
	LastAuthenticationString = NULL;
	lpProxyHost = NULL;
	lpProxyPort = NULL;
	lpProxyUserName  = NULL;
	lpProxyPassword = NULL;
	ProxyInitialized = 0;
	memset(lpTmpData,0,sizeof(lpTmpData));
	challenge = NO_AUTH;
	CookieSupported  = 1;
	AutoRedirect	 = 1;
	MaximumRedirects = MAXIMUM_HTTP_REDIRECT_DEPTH;
	return(1);
}
/*******************************************************************************************************/
HTTPAPIHANDLE::~HTTPAPIHANDLE() 
{
	target = 0;
	*targetDNS=0;
	port = 0;
	NeedSSL = 0;
	version=0;
	ThreadID = 0;
	if (AdditionalHeader) free(AdditionalHeader);
	AdditionalHeader = NULL;

	if (Cookie) free(Cookie);
	Cookie = NULL;

	if (UserAgent) free(UserAgent);
	UserAgent= NULL;

	if (DownloadBwLimit) free(DownloadBwLimit);
	DownloadBwLimit = NULL;

	if (DownloadLimit) free(DownloadLimit);
	DownloadLimit = NULL;

	conexion = NULL;
	ClientConnection = NULL;

	AsyncHTTPRequest = 0;
	if (LastRequestedUri)
	{
		free(LastRequestedUri);
		LastRequestedUri = NULL;
	}
	if (LastAuthenticationString) {
		free(LastAuthenticationString);
		LastAuthenticationString = NULL;
	}

	if (lpProxyHost) {
		free(lpProxyHost);
		lpProxyHost = NULL;
	}

	if (lpProxyPort) {
		free(lpProxyPort);
		lpProxyPort = NULL;
	}

	if (lpProxyUserName) {
		free(lpProxyUserName);
		lpProxyUserName  = NULL;
	}

	if (lpProxyPassword) {
		free(lpProxyPassword);
		lpProxyPassword = NULL;
	}
	ProxyInitialized = 0;

	memset(lpTmpData,0,sizeof(lpTmpData));
	challenge = NO_AUTH;
	CookieSupported  = 1;
	AutoRedirect	 = 1;
	MaximumRedirects = MAXIMUM_HTTP_REDIRECT_DEPTH;
}

/*******************************************************************************************************/
int HTTPAPIHANDLE::SetHTTPConfig(int opt,int parameter)
{
	char tmp[12];
	sprintf(tmp,"%i",parameter);
	switch (opt)
	{
		case ConfigSSLConnection:
			NeedSSL = parameter;
		break;
		case ConfigProxyInitialized:
			ProxyInitialized=parameter;
			break;

		case ConfigAsyncronousProxy:
			AsyncHTTPRequest = parameter;
			break;

		case ConfigMaxDownloadSpeed:
			if (DownloadBwLimit) free(DownloadBwLimit);
			DownloadBwLimit = strdup(tmp);
			break;

		case ConfigProxyPort:
			if (lpProxyPort) free(lpProxyPort);
			if (parameter) {
				lpProxyPort=strdup(tmp);
			} else {
				lpProxyPort=NULL;
			}
			break;
		case ConfigProtocolversion:
			version=parameter;
			break;
		case ConfigMaxDownloadSize:
			if (DownloadLimit) free(DownloadLimit);
			if (parameter) {
				DownloadLimit = strdup(tmp);
			} else {
				DownloadLimit = NULL;
			}
			break;
		case ConfigCookieHandling:
			CookieSupported=parameter;
			break;
		case ConfigAutoredirect:
			AutoRedirect=parameter;
			break;
		default:
			return(-1);
	}
	return(1);

}


/*******************************************************************************************************/
int HTTPAPIHANDLE::SetHTTPConfig(int opt,HTTPCSTR parameter)
{

	switch (opt)
	{
	case ConfigAsyncronousProxy:
			AsyncHTTPRequest = atoi(parameter);
		break;

	case ConfigMaxDownloadSpeed:
		if (DownloadBwLimit) free(DownloadBwLimit);
		if (parameter)
		{			 
			DownloadBwLimit = strdup(parameter);
		} else {
			DownloadBwLimit = NULL;
		}
		break;
	case ConfigCookie:
		if (Cookie)
		{
			free(Cookie);
			Cookie= NULL;
		}
		if ( (parameter) && (*parameter) ){			
			if (strnicmp(parameter,"Cookie: ",8)==0) //Validate the cookie parameter
			{
				Cookie=strdup(parameter);
			} else //Add Cookie Header..
			{
				Cookie=(char*)malloc( 8 + strlen(parameter) +1 );
				strcpy(Cookie,"Cookie: ");
				strcpy(Cookie+8,parameter);
			}
		}
		break;

	case ConfigAdditionalHeader:
		if (AdditionalHeader) 
		{
			free(AdditionalHeader);			
		}
		if ( (parameter) && (*parameter) && (strchr(parameter,':')) ) 
		{
			int len2 = (int) strlen(parameter);
			if (memcmp(parameter+len2 -2,"\r\n",2)!=0) {
				AdditionalHeader = (char*)malloc(len2 +2 +1 );
				memcpy(AdditionalHeader,parameter,len2);
				memcpy(AdditionalHeader +len2,"\r\n\x00",3);
			} else {
				AdditionalHeader = strdup(parameter);
			}
		}  else {
			AdditionalHeader=NULL;
		}
		break;

	case ConfigUserAgent:
		if (UserAgent) {
			free(UserAgent);
		}
		if (parameter) {			
			UserAgent= strdup(parameter);
		} else {
			UserAgent=NULL;
		}
		break;
	case ConfigProxyHost:
		if (lpProxyHost) {
			free(lpProxyHost);
			lpProxyHost=NULL;
		}
		//NeedSSL=0;
		if (parameter)
		{
			struct sockaddr_in remote;
			lpProxyHost=strdup(parameter);
			remote.sin_addr.s_addr = inet_addr(lpProxyHost);
			if (remote.sin_addr.s_addr == INADDR_NONE)
			{
				struct hostent *hostend=gethostbyname(lpProxyHost);
				if (!hostend) return(-1);
				memcpy(&remote.sin_addr.s_addr, hostend->h_addr, 4);
			}
			target=remote.sin_addr.s_addr;
		} else  {
			struct sockaddr_in remote;
			lpProxyHost = NULL;
			remote.sin_addr.s_addr = inet_addr(targetDNS);
			if (remote.sin_addr.s_addr == INADDR_NONE)
			{
				struct hostent *hostend=gethostbyname(targetDNS);
				if (!hostend) return(-1);
				memcpy(&remote.sin_addr.s_addr, hostend->h_addr, 4);
			}
			target=remote.sin_addr.s_addr;
		}
		conexion=NULL;
		if (!lpProxyPort) lpProxyPort=strdup("8080");
		break;

	case ConfigProxyPort:
		if (lpProxyPort) free(lpProxyPort);
		if (parameter) {	
			lpProxyPort=strdup(parameter);
		} else {
			lpProxyPort=NULL;
		}
		break;

	case ConfigProxyUser:
		if (lpProxyUserName) {
			free(lpProxyUserName);
		}
		if (parameter) {
			lpProxyUserName=strdup(parameter);
		} else lpProxyUserName=NULL;
		break;

	case ConfigProxyPass:
		if (lpProxyPassword) {
			free(lpProxyPassword);
		}
		if (parameter) {
			lpProxyPassword=strdup(parameter);
		} else lpProxyPassword=NULL;
		break;

	case ConfigProtocolversion:
		if (parameter) {
			version=atoi(parameter);
		} else version=1;
		break;
	case ConfigMaxDownloadSize:
		if (DownloadLimit) free(DownloadLimit);		
		if (parameter) {
			DownloadLimit = strdup(parameter);
		} else {
			DownloadLimit = NULL;
		}
		break;
	case ConfigCookieHandling:
		CookieSupported=atoi(parameter);
		break;
	case ConfigAutoredirect:
			AutoRedirect=atoi(parameter);;
			break;
	default:
		return(-1);

	}
	return(1);
}

/*******************************************************************************************************/
HTTPSTR HTTPAPIHANDLE::GetHTTPConfig(enum HttpOptions opt)
{

	switch(opt)
	{
	case ConfigHTTPHost:
		return (targetDNS);
	case ConfigHTTPPort:
		sprintf(lpTmpData,"%i",port);
		return (lpTmpData);
	case ConfigMaxDownloadSpeed:
		return(NULL);
	case ConfigCookie:
		return ( Cookie );
	case ConfigAdditionalHeader:
		return ( AdditionalHeader );
	case ConfigUserAgent:
		return ( UserAgent);
	case ConfigProxyHost:
		return ( lpProxyHost);
	case ConfigProxyPort:
		return(lpProxyPort);
	case ConfigProxyUser:
		return ( lpProxyUserName );
	case ConfigProxyPass:
		return ( lpProxyPassword );
	case ConfigProtocolversion:
		sprintf(lpTmpData,"%i",version);
		return (lpTmpData);
	case ConfigProxyInitialized:
		if (ProxyInitialized)
		{
			sprintf(lpTmpData,"%i",ProxyInitialized);
			return (lpTmpData);
		}
		break;
	case ConfigSSLConnection:
		if (NeedSSL)
		{
			sprintf(lpTmpData,"%i",NeedSSL);
			return (lpTmpData);
		} 
		break;
	case ConfigMaxDownloadSize:
		return (DownloadLimit);
	case ConfigCookieHandling:
		if (CookieSupported)
		{
			sprintf(lpTmpData,"%i",CookieSupported);
			return (lpTmpData);
		}
		break;
	case ConfigAutoredirect:
		if (AutoRedirect)
		{
			sprintf(lpTmpData,"%i",AutoRedirect);
			return (lpTmpData);
		}
		break;
	}
	return(NULL);
}
/*******************************************************************************************************/






/*******************************************************************************************************/
char *HTTPAPIHANDLE::GetAdditionalHeaderValue(HTTPCSTR value,int n)
{
	char *base,*end;
	end=base=AdditionalHeader;
	if ( (AdditionalHeader) && (value) )
	{
		size_t valuelen = strlen(value);
		while (*end) {
			if (*end=='\n')
			{
				if (strnicmp(base,value,valuelen)==0)
				{
					if (n==0)
					{
						base  = base + valuelen;
						while  (( *base==' ') || (*base==':') )  { base++; }
						size_t len = (end-base);
						char *header=(char*)malloc(len+1);
						memcpy(header,base,len);
						if (header[len-1]=='\r')
						{
							header[len-1]='\0';
						} else {
							header[len]='\0';
						}
						return (header);
					} else
					{
						n--;
					}
				}
				base=end+1;
			}
			end++;
		}
	}
	return(NULL);
}
/*******************************************************************************************************/
	void HTTPAPIHANDLE::SetLastAuthenticationString(char *authstring) {
		if (LastAuthenticationString) free(LastAuthenticationString);
		LastAuthenticationString = authstring;
	}

/*******************************************************************************************************/
	void HTTPAPIHANDLE::SetLastRequestedUri(HTTPCSTR url)
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
/*******************************************************************************************************/
	char *HTTPAPIHANDLE::GetLastRequestedUri(void) 
	{ 
		return LastRequestedUri; 
	};
/*******************************************************************************************************/

