/*
 Copyright (C) 2007 - 2012  fhscan project.
 Andres Tarasco - http://www.tarasco.org/security - http://www.tarlogic.com

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

//-----------------------------------------------------------------------------
 HTTPAPIHANDLE::HTTPAPIHANDLE(void)
 {
 //target = 0;
 *targetDNS = 0;
 *vHost =0;
 port = 0;
 ThreadID = 0;
 NeedSSL = 0;
 version=0;
 DisconnectSocket = 0;
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
AutoRedirect = 1;
MaximumRedirects = MAXIMUM_HTTP_REDIRECT_DEPTH;

}

//-----------------------------------------------------------------------------
 #ifdef IPV6
 int ResolveHost(struct sockaddr_in6 *remote,HTTPSTR lphostname)
 #else
 int ResolveHost(struct sockaddr_in *remote,HTTPSTR lphostname)
 #endif
 {

 #ifdef _UNICODE
 char hostnameA[256];
 sprintf(hostnameA,"%S",lphostname);
 char *hostname = hostnameA;
 #else
 char *hostname = lphostname;
 #endif
 #ifdef IPV6
 remote->sin6_family = AF_INET6;
 int ret = inet_pton(AF_INET6, hostname,  &remote->sin6_addr);
 #else
 remote->sin_family = AF_INET;
 int ret = inet_pton(AF_INET, hostname, &remote->sin_addr);
 #endif
 if (ret == 0)
 {
/*
 struct addrinfo hints, *res, *ressave;
 int n, sockfd;

 memset(&hints, 0, sizeof(struct addrinfo));

 hints.ai_family = family;
 hints.ai_socktype = socktype;

 n = getaddrinfo(hostname, service, &hints, &res);
 sockfd=-1;
 while (res) {
 sockfd = socket(res->ai_family,
 res->ai_socktype,
 res->ai_protocol);

 if (!(sockfd < 0)) {
 if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
 break;

 close(sockfd);
 sockfd=-1;
 }
 res=res->ai_next;
 }

 freeaddrinfo(ressave);
 return sockfd;
 */

#ifdef IPV6
// TODO: En win32 debemos usar http://msdn.microsoft.com/en-us/library/windows/desktop/ms738520(v=vs.85).aspx
struct hostent *hostend = gethostbyname2(hostname, AF_INET6);
#else
struct hostent *hostend = gethostbyname(hostname);
#endif
if (!hostend)
return (0);
#ifdef IPV6
memset((char *)&remote, 0, sizeof(remote));
memcpy((char *)&remote->sin6_addr, hostend->h_addr, hostend->h_length);
remote->sin6_family = hostend->h_addrtype;
#else
memcpy(&remote->sin_addr.s_addr, hostend->h_addr, 4);
#endif
} return (1);

}

int HTTPAPIHANDLE::InitHandle(HTTPSTR hostname, unsigned short HTTPPort,
	int ssl) {
#ifdef IPV6
struct sockaddr_in6 remote;
#else
struct sockaddr_in remote;
#endif
int resolved = ResolveHost(&remote, hostname);
if (!resolved)
return (0);

/*
 #ifdef IPV6
 struct sockaddr_in6 remote;
 remote.sin6_family = AF_INET6;
 #else
 struct sockaddr_in remote;
 remote.sin_family = AF_INET;          // request IPv4
 #endif
 #ifdef _UNICODE
 char hostnameA[256];
 sprintf(hostnameA,"%S",hostname);
 #ifdef IPV6
 int ret = inet_pton(AF_INET6, hostnameA,  &remote.sin6_addr);
 #else
 int ret = inet_pton(AF_INET, hostnameA,  &remote.sin_addr);
 //remote.sin_addr.s_addr = inet_addr(hostnameA);
 #endif
 #else
 #ifdef IPV6
 int ret = inet_pton(AF_INET6, hostname, &remote.sin6_addr);
 #else
 remote.sin_addr.s_addr = inet_addr(hostname);
 #endif
 #endif

 #ifdef IPV6
 if (ret == 0)
 #else
 if (remote.sin_addr.s_addr == INADDR_NONE)
 #endif
 {
 #ifdef _UNICODE
 //TODO: usar getnameinfo() con IPV6
 struct hostent *hostend=gethostbyname(hostnameA);
 #else
 struct hostent *hostend=gethostbyname(hostname);
 #endif
 if (!hostend)
 {
 return(0);
 }
 memcpy(&remote.sin_addr.s_addr, hostend->h_addr, 4);
 }
 */
// target=remote.sin_addr.s_addr;
_tcsncpy(targetDNS, hostname, sizeof(targetDNS) - 1);
targetDNS[sizeof(targetDNS) / sizeof(HTTPCHAR) - 1] = _T('\0');
port = HTTPPort;

NeedSSL = ssl;
version = 1;
#ifdef __WIN32__RELEASE__
ThreadID = GetCurrentThreadId();
#else
ThreadID = pthread_self();
#endif

AdditionalHeader = NULL;
Cookie = NULL;
UserAgent = NULL;
DownloadBwLimit = NULL;
DownloadLimit = NULL;
conexion = NULL;
ClientConnection = NULL;
AsyncHTTPRequest = 0;
LastRequestedUri = NULL;
LastAuthenticationString = NULL;
lpProxyHost = NULL;
lpProxyPort = NULL;
lpProxyUserName = NULL;
lpProxyPassword = NULL;
ProxyInitialized = 0;
memset(lpTmpData, 0, sizeof(lpTmpData));
challenge = NO_AUTH;
CookieSupported = 1;
AutoRedirect = 1;
MaximumRedirects = MAXIMUM_HTTP_REDIRECT_DEPTH;
return (1);
}

//-----------------------------------------------------------------------------
 HTTPAPIHANDLE::~HTTPAPIHANDLE() {
 //	target = 0;
 *targetDNS = 0;
 port = 0;
 NeedSSL = 0;
 version = 0;
 ThreadID = 0;
 if (AdditionalHeader)
 free(AdditionalHeader);
 AdditionalHeader = NULL;

 if (Cookie)
 free(Cookie);
 Cookie = NULL;

 if (UserAgent)
 free(UserAgent);
 UserAgent = NULL;

 if (DownloadBwLimit)
 free(DownloadBwLimit);
 DownloadBwLimit = NULL;

 if (DownloadLimit)
 free(DownloadLimit);
 DownloadLimit = NULL;

 conexion = NULL;
 ClientConnection = NULL;

 AsyncHTTPRequest = 0;
 if (LastRequestedUri) {
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
 lpProxyUserName = NULL;
 }

 if (lpProxyPassword) {
 free(lpProxyPassword);
 lpProxyPassword = NULL;
 }
 ProxyInitialized = 0;

 memset(lpTmpData, 0, sizeof(lpTmpData));
 challenge = NO_AUTH;
 CookieSupported = 1;
 AutoRedirect = 1;
 MaximumRedirects = MAXIMUM_HTTP_REDIRECT_DEPTH;
 }

//-----------------------------------------------------------------------------
int HTTPAPIHANDLE::SetHTTPConfig(int opt, int parameter) {
HTTPCHAR tmp[12];
_stprintf(tmp, _T("%i"), parameter);
switch (opt) {
case ConfigDisconnectConnection:
DisconnectSocket = parameter;
break;

case ConfigSSLConnection:
NeedSSL = parameter;
break;
case ConfigProxyInitialized:
ProxyInitialized = parameter;
break;

case ConfigAsyncronousProxy:
AsyncHTTPRequest = parameter;
break;

case ConfigMaxDownloadSpeed:
if (DownloadBwLimit)
free(DownloadBwLimit);
DownloadBwLimit = _tcsdup(tmp);
break;

case ConfigProxyPort:
if (lpProxyPort)
free(lpProxyPort);
if (parameter) {
lpProxyPort = _tcsdup(tmp);
}
else {
lpProxyPort = NULL;
}
break;
case ConfigProtocolversion:
version = parameter;
break;
case ConfigMaxDownloadSize:
if (DownloadLimit)
free(DownloadLimit);
if (parameter) {
DownloadLimit = _tcsdup(tmp);
}
else {
DownloadLimit = NULL;
}
break;
case ConfigCookieHandling:
CookieSupported = parameter;
break;
case ConfigAutoredirect:
AutoRedirect = parameter;
break;
default:
return (-1);
}
return (1);

}

//-----------------------------------------------------------------------------
 int HTTPAPIHANDLE::SetHTTPConfig(int opt, HTTPCSTR parameter) {

 switch (opt) {
 case ConfigAsyncronousProxy:
 AsyncHTTPRequest = _tstoi(parameter);
 break;

 case ConfigMaxDownloadSpeed:
 if (DownloadBwLimit)
 free(DownloadBwLimit);
 if (parameter) {
 DownloadBwLimit = _tcsdup(parameter);
 }
 else {
 DownloadBwLimit = NULL;
 }
 break;
 case ConfigCookie:
 if (Cookie) {
 free(Cookie);
 Cookie = NULL;
 }
 if ((parameter) && (*parameter)) {
 if (_tcsncicmp(parameter, _T("Cookie: "), 8) == 0)
 // Validate the cookie parameter
 {
 Cookie = _tcsdup(parameter);
 }
 else // Add Cookie Header..
 {
 Cookie =
 (HTTPCHAR*)malloc((8 + _tcslen(parameter) + 1)*sizeof
 (HTTPCHAR));
 if (Cookie) {
 _tcscpy(Cookie, _T("Cookie: "));
 _tcscpy(Cookie + 8, parameter);
 }
 }
 }
 break;

 case ConfigAdditionalHeader:
 if (AdditionalHeader) {
 free(AdditionalHeader);
 }
 if ((parameter) && (*parameter) && (_tcschr(parameter, _T(':')))) {
 int len2 = (int) _tcslen(parameter);
 if (memcmp(parameter + len2 - 2, _T("\r\n"), 2 * sizeof(HTTPCHAR)) != 0)
 {
 AdditionalHeader =
 (HTTPCHAR*)malloc((len2 + 2 + 1)*sizeof(HTTPCHAR));
 if (AdditionalHeader) {
 memcpy(AdditionalHeader, parameter, len2*sizeof(HTTPCHAR));
 memcpy(AdditionalHeader + len2, _T("\r\n\x00"),
 3*sizeof(HTTPCHAR));
 }
 }
 else {
 AdditionalHeader = _tcsdup(parameter);
 }
 }
 else {
 AdditionalHeader = NULL;
 }
 break;

 case ConfigUserAgent:
 if (UserAgent) {
 free(UserAgent);
 }
 if (parameter) {
 UserAgent = _tcsdup(parameter);
 }
 else {
 UserAgent = NULL;
 }
 break;
 case ConfigProxyHost:
 if (lpProxyHost) {
 free(lpProxyHost);
 lpProxyHost = NULL;
 }
 #ifdef IPV6
 struct sockaddr_in6 remote;
 #else
 struct sockaddr_in remote;
 #endif

 if (parameter) {
 int resolved = ResolveHost(&remote,(HTTPSTR)parameter);
 if (!resolved) return (0);
 lpProxyHost = _tcsdup(parameter);
 } else {
 lpProxyHost = NULL;
 int resolved = ResolveHost(&remote,targetDNS);
 }
 //		target = remote.sin_addr.s_addr;
 conexion = NULL;
 if (!lpProxyPort)
 lpProxyPort = _tcsdup(_T("8080"));
 break;

 case ConfigProxyPort:
 if (lpProxyPort)
 free(lpProxyPort);
 if (parameter) {
 lpProxyPort = _tcsdup(parameter);
 }
 else {
 lpProxyPort = NULL;
 }
 break;

 case ConfigProxyUser:
 if (lpProxyUserName) {
 free(lpProxyUserName);
 }
 if (parameter) {
 lpProxyUserName = _tcsdup(parameter);
 }
 else
 lpProxyUserName = NULL;
 break;

 case ConfigProxyPass:
 if (lpProxyPassword) {
 free(lpProxyPassword);
 }
 if (parameter) {
 lpProxyPassword = _tcsdup(parameter);
 }
 else
 lpProxyPassword = NULL;
 break;

 case ConfigProtocolversion:
 if (parameter) {
 version = _tstoi(parameter);
 }
 else
 version = 1;
 break;
 case ConfigMaxDownloadSize:
 if (DownloadLimit)
 free(DownloadLimit);
 if (parameter) {
 DownloadLimit = _tcsdup(parameter);
 }
 else {
 DownloadLimit = NULL;
 }
 break;
 case ConfigCookieHandling:
 if (parameter) {
 CookieSupported = _tstoi(parameter);
 }
 else {
 CookieSupported = 0;
 }
 break;
 case ConfigAutoredirect:
 if (parameter) {
 AutoRedirect = _tstoi(parameter); ;
 }
 else {
 AutoRedirect = 0;
 }
 break;
 case ConfigHTTPHost:
 if (parameter) {
 _tcsncpy(vHost,parameter,sizeof(vHost)/sizeof(HTTPCHAR));
 } else {
 vHost[0]=_T('\0');
 }
 break;
 default:
 printf("[-] Warning Unknown option 0x%X\r\n",opt);
 return (-1);

 }
 return (1);
 }

//-----------------------------------------------------------------------------
HTTPSTR HTTPAPIHANDLE::GetHTTPConfig(enum HttpOptions opt) {

switch (opt) {
case ConfigHTTPHost:
if (vHost[0])
return (vHost);
else
return (targetDNS);
case ConfigHTTPPort:
_stprintf(lpTmpData, _T("%i"), port);
return (lpTmpData);
case ConfigMaxDownloadSpeed:
return (NULL);
case ConfigCookie:
return (Cookie);
case ConfigAdditionalHeader:
return (AdditionalHeader);
case ConfigUserAgent:
return (UserAgent);
case ConfigProxyHost:
return (lpProxyHost);
case ConfigProxyPort:
return (lpProxyPort);
case ConfigProxyUser:
return (lpProxyUserName);
case ConfigProxyPass:
return (lpProxyPassword);
case ConfigProtocolversion:
_stprintf(lpTmpData, _T("%i"), version);
return (lpTmpData);
case ConfigProxyInitialized:
if (ProxyInitialized) {
_stprintf(lpTmpData, _T("%i"), ProxyInitialized);
return (lpTmpData);
}
break;
case ConfigSSLConnection:
if (NeedSSL) {
_stprintf(lpTmpData, _T("%i"), NeedSSL);
return (lpTmpData);
}
break;
case ConfigMaxDownloadSize:
return (DownloadLimit);
case ConfigCookieHandling:
if (CookieSupported) {
_stprintf(lpTmpData, _T("%i"), CookieSupported);
return (lpTmpData);
}
break;
case ConfigAutoredirect:
if (AutoRedirect) {
_stprintf(lpTmpData, _T("%i"), AutoRedirect);
return (lpTmpData);
}
break;
}
return (NULL);
}

//-----------------------------------------------------------------------------
HTTPCHAR *HTTPAPIHANDLE::GetAdditionalHeaderValue(const HTTPCHAR *value, int n)
{
HTTPCHAR *base, *end;
end = base = AdditionalHeader;
if ((AdditionalHeader) && (value)) {
size_t valuelen = _tcslen(value);
while (*end) {
if (*end == _T('\n')) {
	if (_tcsncicmp(base, value, valuelen) == 0) {
		if (n == 0) {
			base = base + valuelen;
			while ((*base == _T(' ')) || (*base == _T(':'))) {
				base++;
			}
			size_t len = (end - base);
			HTTPCHAR *header = (HTTPCHAR*)malloc(len + 2);
			if (!header) {
				return (NULL);
			}
			else {
				memcpy(header, base, len);
				if (header[len - 1] == _T('\r')) {
					header[len - 1] = _T('\0');
				}
				else {
					header[len] = _T('\0');
				}
				return (header);
			}

		}
		else {
			n--;
		}
	}
	base = end + 1;
}
end++;
}
}
return (NULL);
}

//-----------------------------------------------------------------------------
 void HTTPAPIHANDLE::SetLastAuthenticationString(HTTPCHAR *authstring) {
 if (LastAuthenticationString)
 free(LastAuthenticationString);
 LastAuthenticationString = authstring;
 }

//-----------------------------------------------------------------------------
void HTTPAPIHANDLE::SetLastRequestedUri(HTTPCSTR url) {
if (LastRequestedUri)
free(LastRequestedUri);
if (url) {
LastRequestedUri = _tcsdup(url);
}
else {
LastRequestedUri = NULL;
}

}
//-----------------------------------------------------------------------------
 HTTPCHAR *HTTPAPIHANDLE::GetLastRequestedUri(void) {
 return LastRequestedUri;
 };
//-----------------------------------------------------------------------------
