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
#include "Build.h"
#include "HTTP.h"
#include "ConnectionHandling.h"
#include "CookieHandling.h"
#include "Encoding_Deflate.h"
#ifdef __WIN32__RELEASE__
#pragma comment(lib,"ws2_32.lib")
#endif

#include <iostream>
#include <string>
using namespace std;


#define PURGETIME						25  //25 secconds
#define MAX_INACTIVE_CONNECTION 		10000000 *PURGETIME
#define FHSCANUSERAGENT 				_T("Mozilla/5.0 (compatible; MSIE 7.0; FHScan Core 1.4)")
#define MAX_HEADER_SIZE					8192
#define SERVER_NAME						_T("FSCAN HTTP Proxy")
#define RFC1123FMT						_T("%a, %d %b %Y %H:%M:%S GMT")

struct params {
	void *classptr;
	void *ListeningConnectionptr;
};

/*
- TODO:
- Allow local and remote DNS resolution when working against a Global HTTP proxy
- Replace char , "const char", "const HTTPSTR" and "HTTPSTR" with HTTPCHR / HTTPCSTR / HTTPSTR to migrate the core to wchar
*/
/*******************************************************************************************************/
/*******************************************************************************************************/

/*******************************************************************************************************/
/*******************************************************************************************************/
int ThreadFunc(void *foo)
{
	HTTPAPI *api = (HTTPAPI*)foo;
	api->CleanConnectionTable(NULL);
	return(0);
}

/*******************************************************************************************************/
HTTPAPI::HTTPAPI()
{
#ifdef __WIN32__RELEASE__
	WSAStartup( MAKEWORD(2,2), &ws );
#endif

	for(int i=0;i<MAXIMUM_OPENED_HANDLES;i++) HTTPHandleTable[i]=NULL;

	for (int i = 0;i< MAX_OPEN_CONNECTIONS; i++)
	{
		Connection_Table[i] = new ConnectionHandling;
		Connection_Table[i]->Connectionid = i;
	}

	FHScanUserAgent= _tcsdup(FHSCANUSERAGENT);

	HandleLock.InitThread((void*)ThreadFunc,(void*)this); 

	HTTPCallBack.SetHTTPApiInstance((void*)this);
#ifdef _ZLIB_SUPPORT_
	HTTPCallBack.RegisterHTTPCallBack( CBTYPE_CLIENT_REQUEST | CBTYPE_CLIENT_RESPONSE, (HTTP_IO_REQUEST_CALLBACK)CBDeflate,_T("HTTP Gzip / Deflate decoder"));
#endif
	BindPort = 0;
	COOKIE =  new CookieStatus();
}
/*******************************************************************************************************/
HTTPAPI::~HTTPAPI()
{
	if (BindPort)
	{
		StopHTTPProxy();
	}
	HandleLock.EndThread();

	for (int i = 0;i< MAX_OPEN_CONNECTIONS; i++)
	{
		delete Connection_Table[i]; 	
	}

	for(int i=0;i<MAXIMUM_OPENED_HANDLES;i++)
	{
		if (HTTPHandleTable[i])
		{
			delete HTTPHandleTable[i];
			HTTPHandleTable[i] = NULL;
		}
	}
	if (FHScanUserAgent)
	{
		free(FHScanUserAgent);
		FHScanUserAgent=NULL;
	}
	delete COOKIE;

#ifdef __WIN32__RELEASE__
	WSACleanup();
#endif

}
/*******************************************************************************************************/
int HTTPAPI::SetHTTPConfig(HTTPHANDLE HTTPHandle,enum HttpOptions opt, HTTPCSTR parameter)
{
	if (HTTPHandle == GLOBAL_HTTP_CONFIG)
	{
		return ( GlobalHTTPCoreApiOptions.SetHTTPConfig(opt,parameter) );
	} else
	{
		HTTPAPIHANDLE *RealHTTPHandle = GetHTTPAPIHANDLE(HTTPHandle);
		if (RealHTTPHandle)
		{
			return ( RealHTTPHandle->SetHTTPConfig(opt,parameter) );
		}
	}
	return(0);
}
/*******************************************************************************************************/
int HTTPAPI::SetHTTPConfig(HTTPHANDLE HTTPHandle,enum HttpOptions opt, int parameter)
{
	if (HTTPHandle == GLOBAL_HTTP_CONFIG)
	{
		return ( GlobalHTTPCoreApiOptions.SetHTTPConfig(opt,parameter) );
	} else
	{
		HTTPAPIHANDLE *RealHTTPHandle = GetHTTPAPIHANDLE(HTTPHandle);
		if (RealHTTPHandle)
		{
			return ( RealHTTPHandle->SetHTTPConfig(opt,parameter) );
		}
	}
	return(0);
}
/*******************************************************************************************************/
HTTPSTR	HTTPAPI::GetHTTPConfig(HTTPHANDLE HTTPHandle,enum HttpOptions opt)
{
	if (HTTPHandle == GLOBAL_HTTP_CONFIG)
	{
		return ( GlobalHTTPCoreApiOptions.GetHTTPConfig(opt) );
	} else
	{
		HTTPAPIHANDLE *RealHTTPHandle = GetHTTPAPIHANDLE(HTTPHandle);
		if (RealHTTPHandle)		
		{
			return ( RealHTTPHandle->GetHTTPConfig(opt) );
		} 
	}
	return(0);
}
/*******************************************************************************************************/
HTTPHANDLE HTTPAPI::InitHTTPConnectionHandle(HTTPSTR lpHostName,int port,int ssl)
{
	class HTTPAPIHANDLE *HTTPHandle= new HTTPAPIHANDLE;
	if (HTTPHandle->InitHandle(lpHostName,port,ssl))
	{
		HandleLock.LockMutex();
		for (int i=0;i<MAXIMUM_OPENED_HANDLES;i++)
		{
			if (HTTPHandleTable[i]==NULL)
			{
				HTTPHandleTable[i]=HTTPHandle;
				HandleLock.UnLockMutex();

				HTTPHandle->SetHTTPConfig(ConfigCookieHandling,GlobalHTTPCoreApiOptions.GetHTTPConfig(ConfigCookieHandling));
				HTTPHandle->SetHTTPConfig(ConfigAutoredirect,  GlobalHTTPCoreApiOptions.GetHTTPConfig(ConfigAutoredirect));

				if (GlobalHTTPCoreApiOptions.GetHTTPConfig(ConfigProxyHost) )
				{
					HTTPHandle->SetHTTPConfig(ConfigProxyHost,GlobalHTTPCoreApiOptions.GetHTTPConfig(ConfigProxyHost));
					HTTPHandle->SetHTTPConfig(ConfigProxyPort,GlobalHTTPCoreApiOptions.GetHTTPConfig(ConfigProxyPort));
					if (GlobalHTTPCoreApiOptions.GetHTTPConfig(ConfigProxyUser))
					{
						HTTPHandle->SetHTTPConfig(ConfigProxyUser,GlobalHTTPCoreApiOptions.GetHTTPConfig(ConfigProxyUser));
						HTTPHandle->SetHTTPConfig(ConfigProxyPass,GlobalHTTPCoreApiOptions.GetHTTPConfig(ConfigProxyPass));
					}
					/*set additional Global HTTP options if needed ... */
				}
				return(i);
			}
		}
		HandleLock.UnLockMutex();
	}
	delete HTTPHandle;
	return(-1);
}
/*******************************************************************************************************/
HTTPHANDLE	HTTPAPI::InitHTTPConnectionHandle(HTTPSTR lpHostName,int port) 
{  
	return InitHTTPConnectionHandle(lpHostName,port,0); 
}
/*******************************************************************************************************/

int HTTPAPI::EndHTTPConnectionHandle(HTTPHANDLE UserHandle)
{
	if ((UserHandle>=0) && (UserHandle<MAXIMUM_OPENED_HANDLES))
	{
		HandleLock.LockMutex();
		if (HTTPHandleTable[UserHandle]!=NULL)
		{
			delete HTTPHandleTable[UserHandle];
			HTTPHandleTable[UserHandle] = NULL;
			HandleLock.UnLockMutex();
			return(1);
		}
		HandleLock.UnLockMutex();
	}
	return(0);
}
/*******************************************************************************************************/
class HTTPAPIHANDLE *HTTPAPI::GetHTTPAPIHANDLE(HTTPHANDLE HTTPHandle)
{
	if ((HTTPHandle>=0) && (HTTPHandle<MAXIMUM_OPENED_HANDLES) )
	{
		return(HTTPHandleTable[HTTPHandle]);
	}
	return (NULL);
}

/*******************************************************************************************************/
void  HTTPAPI::CleanConnectionTable(LPVOID *unused)
{

#ifdef __WIN32__RELEASE__
	FILETIME fcurrenttime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER LastUsedTime;
#else
	time_t fcurrenttime;
#endif
	while(1)
	{
		ConnectionTablelock.LockMutex();

#ifdef __WIN32__RELEASE__
		GetSystemTimeAsFileTime(&fcurrenttime);
		CurrentTime.LowPart=fcurrenttime.dwLowDateTime;
		CurrentTime.HighPart=fcurrenttime.dwHighDateTime;
#else
		time(&fcurrenttime);
#endif
		for(int i=0; i<MAX_OPEN_CONNECTIONS;i++)
		{
			if ( (Connection_Table[i]->GetTarget()!=TARGET_FREE) && (!Connection_Table[i]->Getio())  )
			{
#ifdef __WIN32__RELEASE__
				LastUsedTime.HighPart= Connection_Table[i]->GetLastConnectionActivityTime().dwHighDateTime;
				LastUsedTime.LowPart= Connection_Table[i]->GetLastConnectionActivityTime().dwLowDateTime;
				if ( (CurrentTime.QuadPart - LastUsedTime.QuadPart) > MAX_INACTIVE_CONNECTION )
#else
				if ( (fcurrenttime - Connection_Table[i]->GetLastConnectionActivityTime())> MAX_INACTIVE_CONNECTION )
#endif
				{

#ifdef _DBG_
					printf("DBG: Removing connection %3.3i against %s:%i \n",i,Connection_Table[i]->GettargetDNS(),Connection_Table[i]->GetPort());
#endif
					Connection_Table[i]->Disconnect(1);
				}
			}
		}
		ConnectionTablelock.UnLockMutex();
		Sleep(5000);
	}

}

/*******************************************************************************************************/
class ConnectionHandling *HTTPAPI::GetSocketConnection(class HTTPAPIHANDLE *HTTPHandle, HTTPRequest* request)
{
	if (!HTTPHandle) return(NULL);
	ConnectionTablelock.LockMutex();
	int TableIndex=-1;
	int i;
	for(i=0;i<MAX_OPEN_CONNECTIONS;i++)
	{
		if ( (Connection_Table[i]->GetThreadID()==HTTPHandle->GetThreadID()) &&
			(Connection_Table[i]->GetTarget()==HTTPHandle->GetTarget()) && 
			(Connection_Table[i]->GetPort()==HTTPHandle->GetPort()) && 
			(!Connection_Table[i]->Getio()) )
		{
			TableIndex = i;
			#ifdef _DBG_
				printf("[DBG]: %i Reuse Connection %3.3i against %s\n",HTTPHandle->GetThreadID(),FirstIdleSlot,HTTPHandle->GettargetDNS());
			#endif
			break;
		}
	}
	/* There are no stablished connections against the target.*/ 
	/* Search for a free slot into the connection table and store our connection */
	if (TableIndex==-1) 
	{
		for(i=0;i<MAX_OPEN_CONNECTIONS;i++)
		{
			if ( (Connection_Table[i]->GetTarget()==TARGET_FREE) && (!Connection_Table[i]->Getio())  )
			{
				TableIndex = i;
				#ifdef _DBG_
					printf("[DBG]: %i New   Connection %3.3i against %s\n",HTTPHandle->GetThreadID(),FirstIdleSlot,HTTPHandle->GettargetDNS());
				#endif
				break;
			}
		}
	}
	if (TableIndex>=0)
	{
		Connection_Table[TableIndex]->Setio(1);
		ConnectionTablelock.UnLockMutex();
		return(Connection_Table[TableIndex]);
	}
	/*Connection table full. Try Again Later*/
#ifdef _DBG_
		printf("[DBG]: Unable to get a free Socket connection against target. Maybe your application is too aggresive\nUNABLE TO GET FREE SOCKET!!!\n");
#endif
		ConnectionTablelock.UnLockMutex();
		return(NULL);

}

/*******************************************************************************************************/
HTTPResponse* HTTPAPI::DispatchHTTPRequest(HTTPHANDLE HTTPHandle,HTTPRequest* request)
{
	HTTPResponse* response = NULL;
	class ConnectionHandling *conexion;
	unsigned long ret = CBRET_STATUS_NEXT_CB_CONTINUE;
	HTTPAPIHANDLE *RealHTTPApiHandle = GetHTTPAPIHANDLE(HTTPHandle);

	conexion=GetSocketConnection(RealHTTPApiHandle,request);
	if (!conexion)
	{
		return(NULL);
	}
	ret = HTTPCallBack.DoCallBack(CBTYPE_CLIENT_REQUEST ,HTTPHandle,request,response);
	if (ret & CBRET_STATUS_CANCEL_REQUEST)
	{
		return(response);
	}	
	response = conexion->SendAndReadHTTPData(RealHTTPApiHandle,request);
	conexion->Setio(0);
	ret = HTTPCallBack.DoCallBack(CBTYPE_CLIENT_RESPONSE ,HTTPHandle,request,response);

	if (ret & CBRET_STATUS_CANCEL_REQUEST)
	{
		if (response) delete response;
		return(NULL);
	}

	return(response);
}

/*******************************************************************************************************/
HTTPRequest* HTTPAPI::BuildHTTPProxyTunnelConnection( HTTPHANDLE HTTPHandle)
{
	HTTPCHAR	tmp[MAX_HEADER_SIZE];

	_sntprintf(tmp,sizeof(tmp)-1,_T("CONNECT %s:%s HTTP/1.1\r\n\r\n"),GetHTTPConfig(HTTPHandle,ConfigHTTPHost),GetHTTPConfig(HTTPHandle,ConfigHTTPPort));
	HTTPRequest* request = new HTTPRequest;
	request->InitHTTPRequest(tmp);

	if ( (GetHTTPConfig(HTTPHandle,ConfigProxyUser))  && (GetHTTPConfig(HTTPHandle,ConfigProxyPass)) )
	{
		BuildBasicAuthHeader(_T("Proxy-Authorization"),GetHTTPConfig(HTTPHandle,ConfigProxyUser),GetHTTPConfig(HTTPHandle,ConfigProxyPass),tmp,sizeof(tmp));
		request->AddHeader(tmp);
	}
	return(request);
}
/*******************************************************************************************************/


HTTPRequest* HTTPAPI::BuildHTTPRequest(
									HTTPHANDLE HTTPHandle,
									HTTPCSTR VHost,
									HTTPCSTR HTTPMethod,
									HTTPCSTR url,
									HTTPCSTR PostData,
									size_t PostDataSize)
{
	if ( (!url) || (*url!=_T('/')) )
	{
		return ( NULL);
	}

	HTTPCHAR		tmp[MAX_HEADER_SIZE];
	tmp[MAX_HEADER_SIZE-1]=0;

			

	if ( (GetHTTPConfig(HTTPHandle,ConfigProxyHost)) && (!GetHTTPConfig(HTTPHandle,ConfigSSLConnection)) )
	{
		_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("%s http://%s:%s%s HTTP/1.%s\r\n"),HTTPMethod,GetHTTPConfig(HTTPHandle,ConfigHTTPHost),GetHTTPConfig(HTTPHandle,ConfigHTTPPort),url,GetHTTPConfig(HTTPHandle,ConfigProtocolversion));
	} else
	{
		if ( (_tcsnccmp(HTTPMethod,_T("GET"),3)!=0) || (!PostDataSize) )
		{
			_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("%s %s HTTP/1.%s\r\n"),HTTPMethod,url,GetHTTPConfig(HTTPHandle,ConfigProtocolversion));
		} else
		{
			_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("GET %s?%s HTTP/1.%s\r\n"),url,PostData,GetHTTPConfig(HTTPHandle,ConfigProtocolversion));
		}
	}
#ifdef _UNICODE
	wstring rb = tmp;
#else
	string rb = tmp;
#endif


	/* Append the Host header */
	if (VHost)
	{
		_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("Host: %s\r\n"),VHost);
	} else
	{
		_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("Host: %s\r\n"),GetHTTPConfig(HTTPHandle,ConfigHTTPHost));
	}
	rb+=tmp;

	/* Append FHSCAN User Agent */
	if (GetHTTPConfig(HTTPHandle,ConfigUserAgent))
	{
		_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("User-Agent: %s\r\n"),GetHTTPConfig(HTTPHandle,ConfigUserAgent));
	} else
	{
		_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("User-Agent: %s\r\n"),FHScanUserAgent);
	}
	rb += tmp;

	/* Append Custom user headers */
	
	if (GetHTTPConfig(HTTPHandle,ConfigAdditionalHeader))
	{
		rb += GetHTTPConfig(HTTPHandle,ConfigAdditionalHeader);
	}

	if (GetHTTPConfig(HTTPHandle,ConfigCookieHandling))
	{ /* Include Cookies stored into the internal COOKIE bTree */
		HTTPCHAR *lpPath = GetPathFromURL(url);
		HTTPCHAR *ServerCookie = BuildCookiesFromStoredData( GetHTTPConfig(HTTPHandle,ConfigHTTPHost),lpPath,(GetHTTPConfig(HTTPHandle,ConfigSSLConnection)!=NULL));
		free(lpPath);
		if (ServerCookie)
		{
			rb+=_T("Cookie: ");
			rb+=ServerCookie;
			rb+=_T("\r\n");
			free(ServerCookie);
		}
	}

	if (GetHTTPConfig(HTTPHandle,ConfigCookie))
	{ /* Append additional cookies provided by the user - This code should be updated - TODO*/
		_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("%s\r\n"),GetHTTPConfig(HTTPHandle,ConfigCookie));
		rb+=tmp;
	}

	if ( (GetHTTPConfig(HTTPHandle,ConfigProxyHost)) && (!GetHTTPConfig(HTTPHandle,ConfigProxyInitialized)) )
		{   /* Add Keep Alive Headers */
		rb+=_T("Proxy-Connection: Keep-Alive\r\n");
		if ( GetHTTPConfig(HTTPHandle,ConfigProxyUser) )
		{   /* Add Proxy Autentication Headers */
			BuildBasicAuthHeader(_T("Proxy-Authorization"),GetHTTPConfig(HTTPHandle,ConfigProxyUser),GetHTTPConfig(HTTPHandle,ConfigProxyPass),tmp,sizeof(tmp));
			rb+=tmp;
		}
	} else
	{
		rb+=_T("Connection: Keep-Alive\r\n");
	}

	rb+=_T("\r\n");
	HTTPRequest *request = new HTTPRequest;
	request->InitHTTPRequest((HTTPCHAR*)rb.c_str(),(HTTPCHAR*)PostData,PostDataSize);

	if  (  (_tcsnccmp(HTTPMethod,_T("GET"),3)!=0) && ((PostDataSize) ||  (_tcsnccmp(HTTPMethod,_T("POST"),4)==0)))
	{   /* Set the Content-Type header and inspect if have already been added to avoid dups*/
		HTTPSTR contenttype = request->GetHeaderValue(_T("Content-Type:"),0);
		if (contenttype)
		{	
			free(contenttype);
			_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("Content-Length: %i\r\n"),PostDataSize);
		} else
		{
			_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %i\r\n"),PostDataSize);
		}
		request->AddHeader(tmp);
	}
	

	return (request);
}


/**************************************************************************************************/
HTTPSession* HTTPAPI::SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPRequest* request,HTTPCSTR lpUsername,HTTPCSTR lpPassword)
{

	HTTPResponse* 		response=NULL;
	HTTPCHAR		tmp[MAX_HEADER_SIZE];
	tmp[MAX_HEADER_SIZE-1]=0;	
	HTTPCHAR *HTTPMethod = request->GetHTTPMethod();
	HTTPCHAR *url =  request->GetRequestedURL();

	//HTTPCHAR *HTTPMethod = request->GetHTTPMethod()
	//HTTPCHAR url[4096];
//	HTTPCHAR *p,*q;
	int AuthMethod = 0;
	HTTPSTR AuthenticationHeader;

	class HTTPAPIHANDLE *RealHTTPHandle=GetHTTPAPIHANDLE(HTTPHandle);
	if (!RealHTTPHandle) return(NULL);
	if ( (RealHTTPHandle->challenge) && (lpUsername) && (lpPassword) )/* Deal with authentication */
	{
		AuthMethod = 1;
		switch (RealHTTPHandle->challenge)
		{
		case BASIC_AUTH:
			BuildBasicAuthHeader(_T("Authorization"),lpUsername,lpPassword,tmp,MAX_HEADER_SIZE);
			request->AddHeader(tmp);
			break;
		case DIGEST_AUTH:
			if ( (!RealHTTPHandle->GetLastRequestedUri()) || (_tcscmp(RealHTTPHandle->GetLastRequestedUri(),url)!=0) && (RealHTTPHandle->GetLastAuthenticationString()==NULL) )
			{   /*Send another request to check if authentication is required to get the www-authenticate header */
				/* We cant reuse RealHTTPHandle->LastAuthenticationString now*/
				response=DispatchHTTPRequest(HTTPHandle,request);				
				if (!response)
				{
					return(NULL);
				} else 
				{
					RealHTTPHandle->SetLastRequestedUri(url);
					if (response->GetStatus()!=HTTP_STATUS_DENIED)
					{   
						break;
					} else 
					{
						RealHTTPHandle->SetLastAuthenticationString(response->GetHeaderValue(_T("WWW-Authenticate: Digest "),0));
						delete response; response = NULL;
					}
				}
			}
			AuthenticationHeader=CreateDigestAuth(RealHTTPHandle->GetLastAuthenticationString(),lpUsername,lpPassword,HTTPMethod,url,0);
			if (AuthenticationHeader)
			{
				request->AddHeader(AuthenticationHeader);
				free(AuthenticationHeader);
			} else
			{
				RealHTTPHandle->SetLastAuthenticationString(NULL);
			}
			break;

		case NTLM_AUTH:
		case NEGOTIATE_AUTH:
			HTTPCHAR buf1[4096];
			memset(buf1,0,sizeof(buf1));
			_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("Authorization: NTLM %s\r\n"),GetNTLMBase64Packet1((HTTPCHAR*)buf1));
			request->AddHeader(tmp);
			response=DispatchHTTPRequest(HTTPHandle,request);
			request->RemoveHeader(_T("Authorization:"));
			RealHTTPHandle->SetLastRequestedUri(url);
			if (!response)
			{ /* NTLM Negotiation failed */
				return(NULL);
			}
			if (response->GetStatus()==HTTP_STATUS_DENIED)
			{   /*Parse NTLM Message Type 2 */
				HTTPSTR NTLMresponse = response->GetHeaderValue(_T("WWW-Authenticate: NTLM "),0);
				if (!NTLMresponse)  break;  /* WWW-Authenticate: NTLM Header not Found */
				_sntprintf(tmp,MAX_HEADER_SIZE-1,_T("Authorization: NTLM %s\r\n"),GetNTLMBase64Packet3((HTTPCHAR*)buf1,NTLMresponse,lpUsername,lpPassword));
				request->AddHeader(tmp);
				free(NTLMresponse);
				delete(response); response = NULL;

			} else
			{   /* The server does not requiere NTLM authentication or weird anonymous authentication supported? (only NTLM type 1 sent)*/
				break;
			}
			break;
		}
	}

	/* Authentication Headers - if needed - have been added */
	if (!response)
	{
		response=DispatchHTTPRequest(HTTPHandle,request);
	}
	if (!response)
	{
		RealHTTPHandle->SetLastRequestedUri(NULL);
		return(NULL);
	}

	RealHTTPHandle->SetLastRequestedUri(url);
	RealHTTPHandle->challenge=GetSupportedAuthentication(response);


	//HTTPSession* DATA=(HTTPSession*)RealHTTPHandle->ParseReturnedBuffer(request, response);

	HTTPSession *DATA = new HTTPSession;
	DATA->ParseReturnedBuffer(request,response);
	_tcsncpy(DATA->hostname,GetHTTPConfig(HTTPHandle,ConfigHTTPHost),sizeof(DATA->hostname)-1);
	//printf("hostname: %s\n",DATA->hostname);
	DATA->port = _tstoi ( GetHTTPConfig(HTTPHandle,ConfigHTTPPort) );
	//DATA->ip=target;
	DATA->NeedSSL = GetHTTPConfig(HTTPHandle,ConfigSSLConnection)!=NULL;

	//return DATA;


	if ( (DATA) && (RealHTTPHandle->challenge) && (DATA->status==401) && (!AuthMethod) && (lpUsername) && (lpPassword)  )
	{   /* Send Authentication request and return the "authenticated" response */
		HTTPSession* AUTHDATA=SendHttpRequest(HTTPHandle,request,lpUsername,lpPassword);
		if (AUTHDATA)
		{
			DATA->request = NULL; /* We are reutilizing the same request, to avoid deleting memory twice */
			delete DATA;
			return(AUTHDATA);
		}
	}
	if (GetHTTPConfig(HTTPHandle,ConfigCookieHandling))
	{
		HTTPCHAR *lpPath =  GetPathFromURL(url);
		ExtractCookiesFromResponseData(response, lpPath,GetHTTPConfig(HTTPHandle,ConfigHTTPHost));
		free(lpPath);
	}

#define ISREDIRECT(a) ((a==HTTP_STATUS_MOVED) || (a ==HTTP_STATUS_REDIRECT) || (a==HTTP_STATUS_REDIRECT_METHOD)  || (a == HTTP_STATUS_REDIRECT_KEEP_VERB))
	if ( (RealHTTPHandle->IsAutoRedirectEnabled()) && ISREDIRECT(DATA->status) && (RealHTTPHandle->GetMaximumRedirects()) )
	{
		RealHTTPHandle->DecrementMaximumRedirectsCount();
		HTTPCHAR *host = request->GetHeaderValue(_T("Host:"),0);
		HTTPCHAR *Location = GetPathFromLocationHeader(DATA->response,(GetHTTPConfig(HTTPHandle,ConfigSSLConnection)!=NULL),host);
		free(host);

		if (Location)
		{
			HTTPSession* RedirectedData = SendHttpRequest(HTTPHandle,NULL,_T("GET"),Location,NULL,0,lpUsername,lpPassword);
			free(Location);
			if (RedirectedData)
			{
				delete DATA;
				return (RedirectedData);
			}
		}
	}
	RealHTTPHandle->ResetMaximumRedirects();
	return (DATA);


}
/*******************************************************************************************/
HTTPSession* HTTPAPI::SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPCSTR HTTPMethod,HTTPCSTR lpPath)
{
	return SendHttpRequest(HTTPHandle,NULL,HTTPMethod,lpPath,NULL,0,NULL,NULL);
}
/*******************************************************************************************/
HTTPSession* HTTPAPI::SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPCSTR HTTPMethod,HTTPCSTR lpPath,HTTPCSTR PostData)
{
	if  (PostData)
	{
		return SendHttpRequest(HTTPHandle,NULL,HTTPMethod,lpPath,PostData,_tcslen(PostData),NULL,NULL);
	} else
	{
		return SendHttpRequest(HTTPHandle,NULL,HTTPMethod,lpPath,NULL,0,NULL,NULL);
	}
}
/*******************************************************************************************/
HTTPSession* HTTPAPI::SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPCSTR HTTPMethod,HTTPCSTR lpPath,HTTPCSTR PostData,HTTPCSTR lpUsername,HTTPCSTR lpPassword)
{
	return SendHttpRequest(HTTPHandle,NULL,HTTPMethod,lpPath,PostData,_tcslen(PostData),lpUsername,lpPassword);	
}
/*******************************************************************************************/
HTTPSession* HTTPAPI::SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPCSTR VHost,HTTPCSTR HTTPMethod,HTTPCSTR lpPath,HTTPCSTR PostData,size_t PostDataSize,HTTPCSTR lpUsername,HTTPCSTR lpPassword)
{

	if (GetHTTPConfig(HTTPHandle,ConfigProxyHost) && (GetHTTPConfig(HTTPHandle,ConfigSSLConnection)) && (!GetHTTPConfig(HTTPHandle,ConfigProxyInitialized)) )
	{
		HTTPRequest* ProxyConnectRequest = BuildHTTPProxyTunnelConnection(HTTPHandle);
		HTTPSession* ProxyDATA= SendHttpRequest(HTTPHandle,ProxyConnectRequest,NULL,NULL);
		if (ProxyDATA)
		{			
			delete ProxyConnectRequest;
			delete ProxyDATA;
			SetHTTPConfig(HTTPHandle,ConfigProxyInitialized,1);
		}
	}

	HTTPRequest* request=BuildHTTPRequest(HTTPHandle,VHost,HTTPMethod,lpPath,PostData,PostDataSize);
	if (request)
	{
		HTTPSession* DATA = SendHttpRequest(HTTPHandle,request,lpUsername,lpPassword);
		if (DATA)
		{
			
			return(DATA);
		}
		delete request;
	}
	return(NULL);
}
/*******************************************************************************************/
HTTPSession* HTTPAPI::SendHttpRequest(HTTPHANDLE HTTPHandle,HTTPRequest* request)
{
	return SendHttpRequest(HTTPHandle,request,NULL,NULL);
}
/*******************************************************************************************/

HTTPCHAR* HTTPAPI::GetPathFromLocationHeader(HTTPResponse* response, int ssl, const HTTPCHAR* domain)
{
	if (!domain) {
		return(NULL);
	}
	HTTPCHAR *Location = response->GetHeaderValue(_T("Location:"),0);
	if (Location)
	{
		switch (*Location)
		{
		case _T('/'): /* This does not Follows rfc however we should accept it */
			return(Location);
		case _T('h'):
		case _T('H'):
			if (_tcslen(Location)>=8 )
			{
				if (Location[4+ssl]==_T(':'))
				{
					if (_tcsnccmp(Location+7+ssl,domain,_tcslen(domain))==0)
					{
						HTTPCHAR *p=_tcschr(Location+7+ssl,_T('/'));
						if (p)
						{
							HTTPCHAR *q = _tcsdup(p);
							free(Location);
							return(q);
						}
					}
				}
			}
			break;
		default:
			break;
		}
		free(Location);
	}

	return(NULL);

}

/*******************************************************************************************/
HTTPSession*	HTTPAPI::SendHttpRequest(HTTPCSTR Fullurl)
{
	int SSLREQUEST = ( (Fullurl[5]==_T('s')) || ( Fullurl[5]==_T('S')) );
	int port;
	HTTPSTR path = NULL;
	HTTPSTR host =  (HTTPSTR)Fullurl + 7 +  SSLREQUEST;
	HTTPSTR p = _tcschr(host,_T(':'));
	if (!p)
	{
		if (SSLREQUEST)
		{
			port = 443;
		} else
		{
			port = 80;
		}
		HTTPSTR newpath=_tcschr(host,_T('/'));
		if (newpath)
		{
			path=_tcsdup(newpath);
			*newpath=0;
		} else
		{
			path=_tcsdup(_T("/"));
		}
	} else
	{
		*p=0;
		p++;
		HTTPSTR newpath=_tcschr(p,_T('/'));
		if (newpath)
		{
			path=_tcsdup(newpath);
			*newpath=0;
			port = _tstoi(p);
		} else
		{
			port = _tstoi(p);
			path=_tcsdup(_T("/"));
		}
	}

	HTTPHANDLE HTTPHandle = InitHTTPConnectionHandle(host,port,SSLREQUEST);

	if (HTTPHandle !=INVALID_HHTPHANDLE_VALUE)
	{
		HTTPSession* data= SendHttpRequest(HTTPHandle,_T("GET"),path);
		EndHTTPConnectionHandle(HTTPHandle);
		free(path);
		return(data);
	}
	return(NULL);
}





/*******************************************************************************************/
HTTPSession* HTTPAPI::SendRawHTTPRequest(HTTPHANDLE HTTPHandle,HTTPCSTR headers, HTTPCSTR postdata, size_t PostDataSize)
{
	HTTPRequest* request= new HTTPRequest;
	request->InitHTTPRequest((HTTPSTR)headers,(HTTPSTR)postdata, PostDataSize);

	HTTPResponse*		response = DispatchHTTPRequest(HTTPHandle,request);
	if (!response)
	{
		delete request;
		return(NULL);
	}
	HTTPSession *data = new HTTPSession;
	data->ParseReturnedBuffer(request,response);
	_tcsncpy(data->hostname,GetHTTPConfig(HTTPHandle,ConfigHTTPHost),sizeof(data->hostname)-1);
	data->port = _tstoi ( GetHTTPConfig(HTTPHandle,ConfigHTTPPort) );
	//data->ip=target;
	data->NeedSSL = GetHTTPConfig(HTTPHandle,ConfigSSLConnection)!=NULL;

	return data;

}
/*******************************************************************************************/
//! This function is used to disconnect a currently stablished connection.
/*!
\param HTTPHandle Handle of the remote connection.
\param what Cancel only the current request HTTP_REQUEST_CURRENT or blocks all connections against the remote HTTP host with HTTP_REQUEST_ALL.
\note This function is needed to cancel requests like example a CONNECT call sent against a remote
HTTP proxy server by SendRawHTTPRequest()
*/
/*******************************************************************************************/
void HTTPAPI::CancelHTTPRequest(HTTPHANDLE HTTPHandle)
{
	SetHTTPConfig(HTTPHandle,ConfigDisconnectConnection,0);
}
/*******************************************************************************************/
int HTTPAPI::RegisterHTTPCallBack(unsigned int cbType, HTTP_IO_REQUEST_CALLBACK cb,HTTPCSTR Description)
{
	return ( HTTPCallBack.RegisterHTTPCallBack(cbType,cb,Description));
}
/*******************************************************************************************/
void HTTPAPI::BuildBasicAuthHeader(HTTPCSTR Header,HTTPCSTR lpUsername, HTTPCSTR lpPassword,HTTPSTR destination,int dstsize)
{
	HTTPCHAR RawUserPass[750];
	HTTPCHAR EncodedUserPass[1000];

	RawUserPass[sizeof(RawUserPass)/sizeof(HTTPCHAR)-1]=0;
	_sntprintf(RawUserPass,sizeof(RawUserPass)/sizeof(HTTPCHAR)-1,_T("%s:%s"),lpUsername,lpPassword);


	encodebase64(EncodedUserPass,RawUserPass,(int)_tcslen(RawUserPass));
	//int ret = Base64Encode((unsigned HTTPSTR )EncodedUserPass,(unsigned HTTPSTR)RawUserPass,(int)strlen(RawUserPass));	
	//EncodedUserPass[ret]='\0';
	_sntprintf(destination,dstsize-1,_T("%s: Basic %s\r\n"),Header,EncodedUserPass);

}


/*******************************************************************************************/
void HTTPAPI::SendHTTPProxyErrorMessage( ConnectionHandling* connection,int connectionclose, int status,HTTPCSTR protocol, HTTPCSTR title, HTTPCSTR extra_header, HTTPCSTR text )
{
	HTTPCHAR *tmp=(HTTPCHAR*)malloc(10001*sizeof(HTTPCHAR));

	_sntprintf( tmp,10000,_T("<HTML>\n<HEAD><TITLE>%d %s</TITLE></HEAD>\n")
		_T("<BODY BGCOLOR=\"#88a3f1\" TEXT=\"#000000\" LINK=\"#2020ff\" VLINK=\"#4040cc\">\n")
		_T("The HTTP Proxy server found an error while parsing client request</br>\n")
		_T("Error Status: <H4>%d %s</H4>\n")
		_T("<b>Detailed information: </b>%s\n")
		_T("<HR>\n")
		_T("<ADDRESS><A HREF=\"http://www.tarasco.org/security/\">FSCAN HTTP Proxy</A></ADDRESS>\n")
		_T("</BODY>\n")
		_T("</HTML>\n"),
		status, title, status, title,text);

	HTTPResponse* response = this->BuildHTTPProxyResponseHeader( (connection->IsSSLInitialized()!=NULL),connectionclose, status,protocol, title, extra_header, _T("text/html"), (int)_tcslen(tmp), -1 );

	response->SetData(tmp);
	response->SetDataSize(_tcslen(tmp));
	connection->SendHttpResponse(response);
	delete response;
}

/*******************************************************************************************************/
int DispatchHTTPProxyRequestThreadFunc(void *foo)
{
	struct params *param = (struct params *)foo;
	HTTPAPI *api = (HTTPAPI*)param->classptr;
	void *ListeningConnection = param->ListeningConnectionptr;
	free(foo);
	api->DispatchHTTPProxyRequest(ListeningConnection);
	return(0);
}
/*******************************************************************************************************/
void *HTTPAPI::ListenConnection(void *foo)
{
	struct sockaddr_in sin;   
#ifdef __WIN32__RELEASE__
	DWORD dwThread=0;
#else
	pthread_t e_th;
#endif
	//int id=0;
	if ((ListenSocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP))==INVALID_SOCKET)
	{
#ifdef __WIN32__RELEASE__
		printf("HTTPPROXY::ListenConnection(): socket() error: %d\n", WSAGetLastError());
#else
		printf("HTTPPROXY::ListenConnection(): socket() error: %d\n", 0);

#endif
		return (NULL);
	}

	sin.sin_family = AF_INET;
	sin.sin_port = (u_short)htons(BindPort);
	if (*BindIpAdress)
	{
		sin.sin_addr.s_addr  = inet_addr(BindIpAdress);
	} else
	{
		sin.sin_addr.s_addr = INADDR_ANY;
	}
	if (ListenSocket==SOCKET_ERROR) return(0);
	if ( bind(ListenSocket, (struct sockaddr *) &sin, sizeof(sin)) == SOCKET_ERROR )
	{
		printf("HTTPPROXY::WaitForRequests(): bind() error\n");
		return(NULL);
	}
	if ( listen(ListenSocket, HTTP_MAX_CONNECTIONS) == SOCKET_ERROR )
	{
		printf("HTTPPROXY::WaitForRequests(): listen() error\n");
		return(NULL);
	}
#ifdef _DBG_
	printf("WaitForRequests(): Waiting for new connections\n");
#endif

	/*This is our trick to call a class function and send them params */
	do
	{
		//int clientLen= sizeof(struct sockaddr_in);
		ConnectionHandling *connection = new ConnectionHandling;
		connection->Acceptdatasock( ListenSocket );
#ifdef _DBG_
		printf("WaitForRequests(): New Connection accepted from %s\n",connection->GettargetDNS());
#endif
		/* Waiting for incoming connections */
		struct params *param = (struct params *)malloc (sizeof(struct params));
		param->classptr = (void*)this;
		param->ListeningConnectionptr = (void*)connection;
#ifdef __WIN32__RELEASE__
		CreateThread(NULL,0,(LPTHREAD_START_ROUTINE) DispatchHTTPProxyRequestThreadFunc, (LPVOID) param, 0, &dwThread);
		//DispatchHTTPProxyRequestThreadFunc(param);
#else
		void* (*foo)(void*) = (void*(*)(void*))DispatchHTTPProxyRequestThreadFunc;
		pthread_create(&e_th, NULL,foo, (void *)param);
#endif

	} while(1);
}
/****************************************************************************************/
int ListenConnectionThreadFunc(void *foo)
{
	HTTPAPI *api = (HTTPAPI*)foo;
	api->ListenConnection(NULL);
	return(0);
}
/****************************************************************************************/
//! Initializes the HTTP Proxy engine.
/*!
\return This functions returns 1 if initialization succed, 0 if there is an error loading SSL certificates 
or binding to the current address. Value 2 means that the API is already initialized.
\note The HTTP engine should be initialized before interacting with the proxy .
*/
/*******************************************************************************/

int	HTTPAPI::InitHTTPProxy(HTTPCSTR hostname, unsigned short port)
{
	if (BindPort)
	{
		return(0);
	} else
	{
		BindPort=port;
		_tcsncpy(BindIpAdress,hostname,sizeof(BindIpAdress)-1);
		BindIpAdress[sizeof(BindIpAdress)-1]=0;
		ForceDefaultHTTPPorts = 1;
		AnonymousProxy        = 1;
		AsyncHTTPRequest      = 0;
		DisableBrowserCache   = 1;
		ConnectMethodAllowed  = 1;
		UseOriginalUserAgent  = 0;

		int ret = InitProxyCTX();
		if (!ret)
		{
			return(0);
		}
		ProxyEngine.InitThread((void*)ListenConnectionThreadFunc,(void*)this);
		/* This is disabled by default in our Proxy server */
		this->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigCookieHandling,0);
		this->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigAutoredirect,0);
		return(1);
	}
}
/*******************************************************************************/
int	HTTPAPI::InitHTTPProxy(HTTPCSTR hostname, HTTPCSTR port)
{
	return  ( InitHTTPProxy(hostname,_tstoi(port)) );
}
/*******************************************************************************/
int	HTTPAPI::StopHTTPProxy(void)
{
	if (!BindPort)
	{
		return(0);
	}
	BindPort = 0;
	memset( BindIpAdress,0,sizeof(BindIpAdress));
	ProxyEngine.EndThread();
	return  (1);

}

/* some proxy defines */
#define REQUEST_ACCEPTED						0
#define BAD_REQUEST_NO_REQUEST_FOUND 			1
#define BAD_REQUEST_CANT_PARSE_REQUEST 			2
#define BAD_REQUEST_NULL_URL					3

/*******************************************************************************/
//! This is the main HTTP Proxy function that reads for user requests and translates them to requests sent against remote HTTP hosts.
/*!
\param ListeningConnection pointer to an ConnectionHandling struct created when accepted an incoming connection.
\note This function is exported by the HTTPAPI class and must only be called Threaded from ListenConnection();
*/
/*******************************************************************************/
int HTTPAPI::DispatchHTTPProxyRequest(void *ListeningConnection)
{

	ConnectionHandling *ClientConnection = (ConnectionHandling *)ListeningConnection;
	HTTPRequest*			ProxyRequest  = NULL;
	HTTPHANDLE			HTTPHandle = INVALID_HHTPHANDLE_VALUE;
	unsigned int		connect = 0;
	unsigned long		ret = 0;
	int					ConnectionClose = 0;

	ClientConnection->SetBioErr(bio_err);
	/* Read an HTTP request from the connected client */
	while ( (!ConnectionClose) && (ProxyRequest=ClientConnection->ReadHTTPProxyRequestData()) )
	{

		if (connect)
		{   /* We are intercepting an HTTPS request. Just replay the request with some minor modifications */
			if (DisableBrowserCache)
			{   /* We can also force HTTP Requests to avoid cache */
				ProxyRequest->RemoveHeader(_T("If-Modified-Since: "));
			}
			if (!UseOriginalUserAgent)
			{   /* We like FhScan, so we will use our User-Agent unless UseOriginalUserAgent is set to true */
				HTTPCHAR tmp[256];
				ProxyRequest->RemoveHeader(_T("User-Agent"));
				_sntprintf(tmp,sizeof(tmp)-1,_T("User-Agent: %s\r\n"),FHScanUserAgent);
				ProxyRequest->AddHeader(tmp);
			}
			/* Call the registered plugins */
			ret = HTTPCallBack.DoCallBack( CBTYPE_PROXY_REQUEST ,HTTPHandle,ProxyRequest,NULL );
			if (ret==CBRET_STATUS_CANCEL_REQUEST)
			{
				SendHTTPProxyErrorMessage( ClientConnection,0, 403,_T("HTTP/1.1"), _T("Blocked Request"), (HTTPSTR) 0, _T("The HTTP request was blocked before sending.") );
			} else 
			{   /* Deliver the HTTP request to the HTTP server */
				HTTPSession* data = SendRawHTTPRequest(HTTPHandle,ProxyRequest->GetHeaders(),ProxyRequest->Data,ProxyRequest->DataSize);

				if (data)
				{
					ret = HTTPCallBack.DoCallBack( CBTYPE_PROXY_RESPONSE ,HTTPHandle,ProxyRequest,data->response);

				if (!AsyncHTTPRequest)
				{   /* Perform minor modifications to the HTTP Response and send it again to the client */
					if (ret==CBRET_STATUS_CANCEL_REQUEST)
					{
						SendHTTPProxyErrorMessage( ClientConnection,0, 403,_T("HTTP/1.1"), _T("Blocked Request"), (HTTPSTR) 0, _T("The HTTP request was blocked after sending.") );
					} else
					{   /* Force The Client to Keep the connection open */

						data->response->RemoveHeader(_T("Connection:"));
						data->response->AddHeader(_T("Connection: Keep-Alive"));

						HTTPSTR header = data->response->GetHeaderValue(_T("Content-Length:"),0);
						if (header)
						{
							size_t DataSize = _tstoi(header);
							if (DataSize != data->response->DataSize)
							{
								/* Fix the Content-Length  header because the server returned bad or Incomplete Response */
								data->response->RemoveHeader(_T("Content-Length:"));
								HTTPCHAR tmp[256];
								_stprintf(tmp,_T("Content-Length: %i"),data->response->DataSize);
								data->response->AddHeader(tmp);
								/* This error happens only if:
								- wrong/malformed HTTP response.
								- The connection have been closed.
								- The HTTP response data was parsed incorrectly.
								To prevent cascade errors, we should close the connection and force the client to reconnect*/
								ProxyRequest->RemoveHeader(_T("Connection: "));
								data->response->AddHeader(_T("Connection: close"));
								ConnectionClose = 1;
							}
							free(header);
						} else
						{   /* Add a missing Content-Length header */
							HTTPCHAR tmp[256];
							_stprintf(tmp,_T("Content-Length: %i"),data->response->DataSize);
							data->response->AddHeader(tmp);
						}									
						ClientConnection->SendHttpResponse(data->response);				
					}
				}
				} else {
					SendHTTPProxyErrorMessage( ClientConnection,0, 403,_T("HTTP/1.1"), _T("Blocked Request"), (HTTPSTR) 0, _T("The HTTP request was blocked before sending.") );
				}
			}
		} else
		{   /* There is still no SSL Tunnel Stablished so,  parse the request as a normal HTTP request */
			HTTPSTR line=NULL;
			HTTPCHAR method[10000];
			HTTPCHAR host[10000];
			HTTPCHAR path[10000];
			int  port = 80;
			HTTPCHAR protocol[10000]=_T("HTTP/1.1");		

			/* Get information from the incoming HTTP Request */
			line=ProxyRequest->GetHeaderValueByID(0);
			if (line)
			{
				if (_tcsnccmp(line,_T("CONNECT "),8)==0)
				{   /*TODO: Check for overflow*/
					if (_stscanf( line, _T("%[^ ] %[^ ] %[^ ]"), method, host, protocol )!=3)
					{
						ret = BAD_REQUEST_CANT_PARSE_REQUEST;
					} else
					{
						HTTPSTR lpPort=_tcschr(host,_T(':'));
						if (lpPort)
						{
							*lpPort=0;
							port=_tstoi(lpPort+1);
						} else
						{
							port=443;
						}
						ret = REQUEST_ACCEPTED;
					}
				} else
				{
					ret = ParseRequest(line, method,  host, path, &port);
				}
			} else
			{
				ret = BAD_REQUEST_CANT_PARSE_REQUEST;
			}

			/* Initialize the Handle to NULL */
			HTTPHandle = INVALID_HHTPHANDLE_VALUE;

			switch (ret)
			{
			case REQUEST_ACCEPTED:	
				/* Initialize the HTTPHandle against the remote host */
				connect = (_tcscmp(method,_T("CONNECT"))==0);
				if ( ForceDefaultHTTPPorts)
				{
					if ( (port ==  80 ) || (port == 443)  )
					{					
						HTTPHandle = InitHTTPConnectionHandle(host,port, connect);
					} else
					{
						SendHTTPProxyErrorMessage( ClientConnection,0, 403,protocol, _T("Blocked Request"), (HTTPSTR) 0, _T("The remote HTTP port is not allowed.") );
					}
				} else
				{
					HTTPHandle = InitHTTPConnectionHandle(host,port, connect);
				}

				if (HTTPHandle == INVALID_HHTPHANDLE_VALUE)
				{
					memset(method,0,sizeof(method));
					_sntprintf(method,sizeof(method)-1,_T(" Unable to resolve the requested host <b>\"%s\"</b>.</br></br>")
						_T("This can be caused by a DNS timeout while resolving the remote address or just because the address you typed is wrong.</br>")
						_T("Click <a href=\"%s%s%s\">here</a> to try again"),host,connect ? _T("https://") : _T("http://"),host,path);
					if (connect) SendHTTPProxyErrorMessage( ClientConnection,1, 503,protocol, _T("Service Unavailable"), (HTTPSTR) 0,method);
					else SendHTTPProxyErrorMessage( ClientConnection,0, 503,protocol, _T("Service Unavailable"), (HTTPSTR) 0,method);
					connect=0;
				} else
				{
					SetHTTPConfig(HTTPHandle,ConfigProtocolversion,line+_tcslen(line)-1);
					if (AsyncHTTPRequest) 
					{
						GetHTTPAPIHANDLE(HTTPHandle)->SetClientConnection(ClientConnection);
					}

					if (_tcscmp(method,_T("CONNECT"))==0) 
					{  /*Initialize the SSL Tunnel and replay the client with a "Connection stablished 200 OK" message*/

						HTTPResponse*  HTTPTunnelResponse= this->BuildHTTPProxyResponseHeader(ClientConnection->IsSSLInitialized()!=NULL,0,200,protocol,_T("Connection established"),_T("Proxy-connection: Keep-alive"),NULL,-1,-1);
						ClientConnection->SendHttpResponse( HTTPTunnelResponse);
						delete HTTPTunnelResponse;

						ClientConnection->SetCTX(ctx);
					} else 
					{   /* Parse the HTTP request Headers before sending */
						unsigned long ret;

						ret = HTTPCallBack.DoCallBack( CBTYPE_PROXY_REQUEST ,HTTPHandle,ProxyRequest,NULL );

						if (ret & CBRET_STATUS_CANCEL_REQUEST)
						{
							SendHTTPProxyErrorMessage( ClientConnection,0, 403,protocol, _T("Blocked Request"), (HTTPSTR) 0, _T("The requested resource was blocked by a registered module.") );
						} else
						{
							HTTPCHAR	 *ClientRequest=NULL;
							size_t       ClientRequestLength  = 0;
							size_t       HeaderLength ;
							HTTPCHAR 		 tmp[256];
							unsigned int id =1;
							HTTPCHAR 		 *p;
							HTTPSTR vhost = ProxyRequest->GetHeaderValue(_T("Host:"),0);


							if  (UseOriginalUserAgent) 
							{   /* By default SendHttpRequest() will append their own user-Agent header, so we must override it */
								SetHTTPConfig(HTTPHandle,ConfigUserAgent,(const HTTPCHAR*)NULL);
							}

							do	
							{  /*Append Browser HTTP Headers to our custom request and ignore some of them*/
								p=ProxyRequest->GetHeaderValueByID(id++);
								if (p)
								{
									if (!SkipHeader(p))
									{ 
										HeaderLength  = _tcslen(p);
										if (!ClientRequestLength  )
										{
											ClientRequest = (HTTPSTR)malloc((HeaderLength  +2 +1)*sizeof(HTTPCHAR));
										} else
										{
											ClientRequest = (HTTPSTR)realloc(ClientRequest,(ClientRequestLength  + HeaderLength  +2 +1)*sizeof(HTTPCHAR));
										}
										memcpy(ClientRequest+ClientRequestLength ,p,HeaderLength*sizeof(HTTPCHAR) );
										ClientRequestLength  += HeaderLength ;
										memcpy(ClientRequest+ClientRequestLength ,_T("\r\n"),2*sizeof(HTTPCHAR));
										ClientRequestLength  += 2;
									} else 
									{
										if ( (UseOriginalUserAgent) && (_tcsnccmp(p,_T("User-Agent:"),11)==0))
										{
											SetHTTPConfig(HTTPHandle,ConfigUserAgent,p+12);
										} 
									}
									free(p);
								} 
							} while (p);


							if (!AnonymousProxy)
							{   /* Append Remote user identification Header */
								_stprintf(tmp,_T("X-Forwarded-For: %s\r\n"),ClientConnection->GettargetDNS());
								HeaderLength  = _tcslen(tmp);
								if (!ClientRequest) 
								{
									ClientRequest = (HTTPSTR)malloc( (HeaderLength  + 1)*sizeof(HTTPCHAR));
								} else 
								{
									ClientRequest = (HTTPSTR)realloc(ClientRequest,(ClientRequestLength  + HeaderLength +1)*sizeof(HTTPCHAR));
								}
								memcpy(ClientRequest+ClientRequestLength ,tmp,HeaderLength*sizeof(HTTPCHAR) );
								ClientRequestLength +=HeaderLength ;
							}

							if (ClientRequest)
							{
								ClientRequest[ClientRequestLength ]=0;
								SetHTTPConfig(HTTPHandle,ConfigAdditionalHeader,ClientRequest);
								free(ClientRequest);
							}
							/* Send request to the remote HTTP Server */
							HTTPSession* data = SendHttpRequest(HTTPHandle,vhost ? vhost : host,method,path,ProxyRequest->Data,ProxyRequest->DataSize,NULL,NULL);

							/* Clean the HTTPHandle options */
							SetHTTPConfig(HTTPHandle,ConfigAdditionalHeader,(const HTTPCHAR*)NULL);
							if (vhost) free(vhost);

							if   (data) 
							{
								/* Parse returned HTTP response and add some extra headers to avoid client disconnection*/
								if ( (data->response) && (data->response->GetHeaderSize()!=0) )
								{
#ifdef _DBG_
									printf("[%3.3i] HandleRequest() - Leida respuesta del servidor Web. Headers Len: %i bytes - Datos: %i bytes\n",ClientConnection->id,data->response->HeaderSize,data->response->DataSize);
									printf("Headers: !%s!\n",data->response->Header);
									if (data->response->DataSize) printf("!%s!\n",data->response->Data);
#endif
									data->response->RemoveHeader(_T("Connection:"));
									data->response->AddHeader(_T("Proxy-Connection: keep-alive"));
									data->response->RemoveHeader(_T("Content-Length:"));
									_stprintf(path,_T("Content-Length: %i"),data->response->DataSize);
									data->response->AddHeader(path);

									ret = HTTPCallBack.DoCallBack( CBTYPE_PROXY_RESPONSE ,HTTPHandle,ProxyRequest,data->response );

									if (!AsyncHTTPRequest)
									{
										if (ret & CBRET_STATUS_CANCEL_REQUEST)
										{
											SendHTTPProxyErrorMessage( ClientConnection,0, 403,protocol, _T("Blocked Request"), (HTTPSTR) 0, _T("The requested resource was blocked by a register module.") );
										} else
										{
											/* Finally, deliver HTTP response */
											ClientConnection->SendHttpResponse( data->response);
										}
									}
								} else
								{
									SendHTTPProxyErrorMessage( ClientConnection,0, 503,protocol, _T("Service Unavailable"), (HTTPSTR) 0, _T("The remote host returned no data.") );
									//TODO: close the connection table (not sure if needed :? )

								}
								//FreeRequest(data);
								delete data;

							} else
							{
								SendHTTPProxyErrorMessage( ClientConnection,0, 504,protocol, _T("Gateway Timeout"), (HTTPSTR) 0, _T("Unable to reach the remote HTTP Server.") );
								//TODO: close the connection table (not sure if needed :? )
							}
						}
						EndHTTPConnectionHandle(HTTPHandle);
						HTTPHandle = INVALID_HHTPHANDLE_VALUE;

					} /*End of HTTP request (Method != "CONNECT") */
				}
				break;
				/* deal with some errors */
			case BAD_REQUEST_NO_REQUEST_FOUND:
				SendHTTPProxyErrorMessage( ClientConnection,1, 400, protocol,_T("Bad Request"), (HTTPSTR) 0, _T("No request found.") );
				ConnectionClose = 1;
				break;
			case BAD_REQUEST_CANT_PARSE_REQUEST:
				SendHTTPProxyErrorMessage(ClientConnection,1,  400, protocol,_T("Bad Request"), (HTTPSTR) 0, _T("Can't parse request.") );
				ConnectionClose = 1;
				break;
			case BAD_REQUEST_NULL_URL:
				SendHTTPProxyErrorMessage( ClientConnection,1, 400,protocol, _T("Bad Request"), (HTTPSTR) 0, _T("Null URL.") );
				ConnectionClose = 1;
				break;
			default:
				SendHTTPProxyErrorMessage( ClientConnection,1, 400, protocol,_T("Bad Request"), (HTTPSTR) 0, _T("OMG! Unknown error =)") );
				ConnectionClose = 1;
				break;
			}			
			if (line) free(line);							
		}
		delete ProxyRequest;
		ProxyRequest=NULL;
	}	
	EndHTTPConnectionHandle(HTTPHandle);
	if (ProxyRequest)
	{
		delete ProxyRequest; 
		ProxyRequest = NULL;
	}
#ifdef _DBG_
	printf("[%3.3i] HandleRequest(): DESCONEXION del Cliente...\n",ClientConnection->id);
#endif
	delete ClientConnection;

	//TODO:
	/*
	- Liberar ClientConnection
	- liberar la informacion SSL de ClientConnection.
	*/
	return(1);
}
/****************************************************************************************/


int HTTPAPI::ParseRequest(HTTPSTR line, HTTPSTR method,  HTTPSTR host, HTTPSTR path, int *port)
{
	int iport;
	HTTPCHAR protocol[10000];
	HTTPCHAR url[10000];


	if ( (!line) || (*line==0)) return (BAD_REQUEST_NO_REQUEST_FOUND);

	if ( _stscanf( line, _T("%[^ ] %[^ ] %[^ ]"), method, url, protocol ) != 3 ) return(BAD_REQUEST_CANT_PARSE_REQUEST);

	if ( url == (HTTPSTR) 0 ) return(BAD_REQUEST_NULL_URL);

	if ( _tcsncicmp( url, _T("http://"), 7 ) == 0 )
	{
		_tcsncpy( url, _T("http"), 4 );	/* make sure it's lower case */
		if ( _stscanf( url, _T("http://%[^:/]:%d%s"), host, &iport, path ) == 3 )
			*port = (unsigned short) iport;
		else if ( _stscanf( url, _T("http://%[^/]%s"), host, path ) == 2 )
			*port = 80;
		else if ( _stscanf( url, _T("http://%[^:/]:%d"), host, &iport ) == 2 )
		{
			*port = (unsigned short) iport;
			_tcscpy(path,_T("/"));
		}
		else if ( _stscanf( url, _T("http://%[^/]"), host ) == 1 )
		{
			*port = 80;
			_tcscpy(path,_T("/"));
		} else
		{
			return (BAD_REQUEST_CANT_PARSE_REQUEST);
		}
	} else
	{
		if ( (ConnectMethodAllowed) && (_tcscmp(method,_T("CONNECT"))==0) )
		{
			HTTPSTR p=_tcschr(url,_T(':'));
			if (p)
			{
				*port = iport=_tstoi(p+1);
				*p=0;
				_tcscpy(host,url);
			}
			else
			{
				return (BAD_REQUEST_CANT_PARSE_REQUEST);
			}
		} else
			return (BAD_REQUEST_CANT_PARSE_REQUEST);	//send_error( sock, 400, "Bad Request", (HTTPSTR) 0, "Unknown URL type." );
	}
	return (REQUEST_ACCEPTED);
}

/*******************************************************************************/
int HTTPAPI::SkipHeader(HTTPSTR header)
{
	struct skipheader
	{
		const HTTPCHAR name[20];
		int len;
	} IgnoreHeaders[]= {
		{ _T("Accept-Encoding:"), 16},
//		{ "Age:",              4},
//		{ "Cache-Control:",   14},
		{ _T("Connection:"),      11},
		{ _T("Content-Length:"),  15},
		{ _T("Host:"),             5},
		{ _T("Keep-Alive:"),      11},
//		{ "Last-Modified:",   14},
		{ _T("Proxy-Connection:"),17},
		{ _T("User-Agent:")      ,11}
	};
	int ret;
	unsigned int i=0;
	do {
		ret=_tcsncicmp(header,IgnoreHeaders[i].name,IgnoreHeaders[i].len);
		if (ret==0) return(1);
		i++;
	} while ((i<sizeof(IgnoreHeaders)/sizeof(struct skipheader)) && (ret>0));

	if ( (DisableBrowserCache)  && (  (_tcsncicmp(header,_T("If-Modified-Since: "),19)==0) || ( _tcsncicmp(header,_T("If-None-Match: "),15)==0)))
	{
		return(1);
	}

	return(0);


}
/*******************************************************************************/
//! This function Allows users to change some HTTP Proxy configuration.
/*!
\param opt this value indicates the kind of data that is going to be modified. Valid options are:\n
- OPT_HTTPPROXY_ALLOWCONNECT (Enables Support of tunneling requests with the HTTP Connect method. Default allowed)
- OPT_HTTPPROXY_ANONYMOUSPROXY (Handle if the proxy is going to add extra headers like X-Forwarded-For. Default Anonymous )
- OPT_HTTPPROXY_ASYNCREQUEST (Does not wait for the full request to be readead and the readead data is sent as received to the client. Default disabled)
- OPT_HTTPPROXY_DISABLECACHE (Includes some extra headers to avoid browser cache, so the resource is retrieved again. Default enabled (cache is disabled)
- OPT_HTTPPROXY_ORIGINALUSERAGENT (Force the HTTP proxy to use the original user agent or use instead a custom fhscan user-agent. Default disabled (custom user-agent sent) )
- OPT_HTTPPROXY_FORCE_DEFAULT_HTTP_PORTS (Allows connecting to non default HTTP ports. Default is enabled. Only port 80 and 443 allowed)
\param parameter pointer to the Current value. These values can be "1" to enable the feature or "0" to disable it.
\return This function doest not return information, as its not needed.
\note if parameter is NULL, the operation is ignored.
/*******************************************************************************/
void HTTPAPI::SetHTTPProxyConfig(enum HttpProxyoptions  opt,HTTPSTR parameter)
{
	if (!parameter) return;
	switch (opt)
	{
	case ProxyAllowConnect:
		ConnectMethodAllowed = _tstoi(parameter);
		break;
	case ProxyAnonymous:
		AnonymousProxy = _tstoi(parameter);
		break;
	case ProxyAsynRequest:
		AsyncHTTPRequest = _tstoi(parameter);
		break;
	case ProxyDisableCache:
		DisableBrowserCache = _tstoi(parameter);
		break;
	case ProxyOriginalUserAgent:
		UseOriginalUserAgent = _tstoi(parameter);
		break;	
	case ProxyDefaultPorts:
		ForceDefaultHTTPPorts = _tstoi(parameter);
		break;
	}
	return;
}

/*******************************************************************************/
/*******************************************************************************/
void HTTPAPI::SetHTTPProxyConfig(enum HttpProxyoptions  opt,int parameter)
{
	switch (opt)
	{
	case ProxyAllowConnect:
		ConnectMethodAllowed = parameter;
		break;
	case ProxyAnonymous:
		AnonymousProxy = parameter;
		break;
	case ProxyAsynRequest:
		AsyncHTTPRequest = parameter;
		break;
	case ProxyDisableCache:
		DisableBrowserCache = parameter;
		break;
	case ProxyOriginalUserAgent:
		UseOriginalUserAgent = parameter;
		break;	
	case ProxyDefaultPorts:
		ForceDefaultHTTPPorts = parameter;
		break;
	}
	return;
}
/*******************************************************************************************/
HTTPCHAR *HTTPAPI::GetPathFromURL(HTTPCSTR url)
{ /* Its assumed that *url == '/' */

	HTTPSTR FullURL=_tcsdup(url);
	HTTPSTR p=FullURL;
	HTTPSTR end = NULL;

	while (*p)
	{
		switch (*p)
		{
		case _T('/'):
			end=p;
			break;
		case _T('?'):
		case _T('&'):
		case _T(';'):
			/* We can be sure that there is not parameters at the url so its recommended to check
			if they exist and avoid them to give us wrong data */
			if (end)
			{
				end[1] =0;
			}
			return(FullURL);
			break;
		}
		p++;
	}
	if (end)
	{
		end[1] =0;
	}
	return(FullURL);
}
/*******************************************************************************************/
HTTPCHAR *HTTPAPI::BuildCookiesFromStoredData( HTTPCSTR TargetDNS, HTTPCSTR path,int secure)
{
	return (COOKIE ->ReturnCookieHeaderFor(TargetDNS,path,secure));

}
/*******************************************************************************************/
void HTTPAPI::ExtractCookiesFromResponseData(HTTPResponse* response, HTTPCSTR lpPath, HTTPCSTR TargetDNS)
{
	if (response)
	{
		int n =0;
		HTTPCHAR *lpCookie = NULL;
		do
		{
			if (lpCookie) free(lpCookie);
			lpCookie = response->GetHeaderValue(_T("Set-Cookie:"),n);
			if (lpCookie)
			{
				//printf("Extraido: %s\n",lpCookie);
				COOKIE->ParseCookieData(lpCookie,lpPath,TargetDNS);
				n++;
			} 
		} while (lpCookie);
	}
}
/*******************************************************************************************/
HTTPResponse* HTTPAPI::BuildHTTPProxyResponseHeader( int isSSLStablished,int closeconnection, int status, HTTPCSTR protocol,const HTTPCHAR* title, const HTTPCHAR* extra_header, const HTTPCHAR* mime_type, int length, time_t mod )
{
	time_t now;
	HTTPCHAR timebuf[100];
	HTTPCHAR headers[10000],tmp[10000];

	now = time( (time_t*) 0 );
	_tcsftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &now ) );
	_stprintf( headers,_T("%s %d %s\r\nServer: %s\r\nDate: %s\r\n"), protocol, status, title,SERVER_NAME,timebuf );

	if ( ( extra_header != (HTTPCHAR*) 0 )  && (*extra_header) ) { 	_stprintf(tmp, _T("%s\r\n"), extra_header );	_tcscat(headers,tmp); }
	if ( mime_type != (HTTPCHAR*) 0 ) 	{ _stprintf( tmp,_T("Content-Type: %s\r\n"), mime_type ); _tcscat(headers,tmp); }
	if ( length >= 0 ) 				{ _stprintf(tmp, _T("Content-Length: %d\r\n"), length );	_tcscat(headers,tmp); }
	if ( mod != (time_t) -1 )		{ _tcsftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &mod ) );	_stprintf( tmp,_T("Last-Modified: %s\r\n"), timebuf ); _tcscat(headers,tmp); }
	if (closeconnection==1)
	{
		if (isSSLStablished)		  
			_tcscpy( tmp,_T("Connection: close\r\n\r\n") );
		else
			_tcscpy( tmp,_T("Proxy-connection: close\r\n\r\n") ); 						  

		_tcscat(headers,tmp);		
	} else  { 
		_tcscat(headers,_T("\r\n")); 
	}
	HTTPResponse *response = new HTTPResponse;
	response->InitHTTPHeaders(headers);
	return(response);
}
/****************************************************************************************/
static int password_cb(char *buf,int num, int rwflag,void *userdata)
{
	if(num<(int)strlen(PASSWORD)+1)
		return(0);
	strcpy(buf,PASSWORD);
	return((int)strlen(PASSWORD));
}


int HTTPAPI::InitProxyCTX(void)
{
	SSL_METHOD *meth;
	/* Load SSL options */
	meth=SSLV23_METHOD();
	ctx=SSL_CTX_NEW(meth);
	if(!(SSL_CTX_USE_CERTIFICATE_CHAIN_FILE((SSL_CTX*)ctx, KEYFILE)))
	{
		printf("# SSL PROXY FATAL ERROR: Unable to read Certificate File\n");
		return(0);
	}
	SSL_CTX_SET_DEFAULT_PASSWD_CB((SSL_CTX*)ctx, password_cb);
	if(!(SSL_CTX_USE_PRIVATEKEY_FILE((SSL_CTX*)ctx,KEYFILE,SSL_FILETYPE_PEM)))
	{
		printf("# SSL PROXY FATAL ERROR: Unable to read key File\n");
		return(0);
	}

	/* Load the CAs we trust*/
	if(!(SSL_CTX_LOAD_VERIFY_LOCATIONS((SSL_CTX*)ctx, CA_LIST,0)))
	{
		printf("# SSL PROXY FATAL ERROR: Unable to read CA LIST\n");
		return(0);
	}
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
	SSL_CTX_SET_VERIFY_DEPTH((SSL_CTX*)ctx,1);
#endif


	DH *ret=0;
	BIO *bio;

	if ((bio=BIO_NEW_FILE(DHFILE,"r")) == NULL)
	{
		printf("# SSL PROXY FATAL ERROR: Unable to open DH file\n");

		return(0);
	}


	ret=(DH*)PEM_READ_BIO_DHPARAMS(bio,NULL,NULL,NULL);
	BIO_FREE(bio);

	if(SSL_CTX_SET_TMP_DH((SSL_CTX*)ctx,ret)<0)
	{
		printf("# SSL PROXY FATAL ERROR: Unable to set DH parameters\n");

		return(0);
	}

	return(1);
}


/*******************************************************************************************************/
enum AuthenticationType HTTPAPI::GetSupportedAuthentication(HTTPResponse *response)
{
	int ret=NO_AUTH;
	int i=0;
	HTTPCHAR *auth;
	const HTTPCHAR AuthNeeded[] = _T("WWW-Authenticate:");

	do 
	{
		auth=response->GetHeaderValue(AuthNeeded,i++);
		if (auth) {
			if (_tcsncicmp (auth, _T("basic"),  5) == 0) {
				if (!(ret & BASIC_AUTH)) ret+=BASIC_AUTH;
			}  else
				if (_tcsncicmp (auth, _T("digest"), 6) == 0) {
					if (!(ret & DIGEST_AUTH)) ret+=DIGEST_AUTH;
				} else
					if (_tcsncicmp (auth, _T("ntlm"),   4) == 0) {
						if (!(ret & NTLM_AUTH)) ret+=NTLM_AUTH;
					} else
						if (_tcsncicmp (auth, _T("Negotiate"),   9) == 0) {
							if (!(ret & NTLM_AUTH)) ret+=NEGOTIATE_AUTH;
						} else {
							if (!(ret & UNKNOWN_AUTH)) ret+=UNKNOWN_AUTH;
						}
						free(auth);
		}
	} while (auth) ;
	
	if (ret != NO_AUTH)
	{
		if (ret & BASIC_AUTH) 	return(BASIC_AUTH);
		if (ret & DIGEST_AUTH) 	return(DIGEST_AUTH);
		if (ret & NTLM_AUTH) 		return(NTLM_AUTH);
		if (ret & NEGOTIATE_AUTH) return(NEGOTIATE_AUTH);
	}
	return(NO_AUTH);
	


}
