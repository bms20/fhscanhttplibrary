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
#include "HTTPRequest.h"

HTTPRequest::HTTPRequest()
{
	Data = NULL;
	DataSize = 0;
	requestedurl = NULL;
	HTTPMethod = NULL;
	BinaryData = 0;
}
/*******************************************************************************************************/
void HTTPRequest::InitHTTPRequest(HTTPCHAR *HTTPHeaders)
{
	InitHTTPHeaders(HTTPHeaders);
}
/*******************************************************************************************************/
void HTTPRequest::InitHTTPRequest(HTTPCHAR *HTTPHeaders, HTTPCHAR *HTTPData)
{
	InitHTTPHeaders(HTTPHeaders);
	Data = _tcsdup(HTTPData);
	DataSize = _tcslen(HTTPData);
}
/*******************************************************************************************************/
void HTTPRequest::InitHTTPRequest(HTTPCHAR *HTTPHeaders, HTTPCHAR* HTTPData, size_t HTTPDataSize)
{
	InitHTTPHeaders(HTTPHeaders);
	Data = (HTTPCHAR*)malloc(HTTPDataSize);
	memcpy(Data,HTTPData,HTTPDataSize);
	DataSize = HTTPDataSize;
	BinaryData = 1;
}
/*******************************************************************************************************/
void HTTPRequest::InitHTTPRequest(HTTPCHAR *HTTPHeaders, size_t HTTPHeaderSize, HTTPCHAR* HTTPData, size_t HTTPDataSize)
{
	Header = (HTTPCHAR*)malloc(HTTPHeaderSize+1);
	memcpy(Header,HTTPHeaders,HTTPHeaderSize);
	Header[HTTPHeaderSize]=0;
	Data =(HTTPCHAR*) malloc(HTTPDataSize);
	memcpy(Data,HTTPData,HTTPDataSize);
	DataSize = HTTPDataSize;
	BinaryData = 1;

}
/*******************************************************************************************************/
#ifdef UNICODE	
void HTTPRequest::InitHTTPRequestA(char *lpBuffer,size_t HTTPHeaderSize, void *HTTPData, size_t HTTPDataSize)
{
char *tmpHeader = malloc(HTTPHeaderSize+1);
memcpy(tmpHeader,lpBuffer,HTTPHeaderSize);
tmpHeader[HTTPHeaderSize]=0;

int ret = MultiByteToWideChar(CP_ACP, 0, tmpHeader, -1, NULL, 1024);
Header = (wchar_t*)malloc(ret +2);
MultiByteToWideChar(CP_ACP, 0, tmpHeader, -1, Header, -1);

	Data = malloc(HTTPDataSize);
	memcpy(Data,HTTPData,HTTPDataSize);
	DataSize = HTTPDataSize;
	BinaryData = 1;

}
#endif

/*******************************************************************************************************/
HTTPRequest::~HTTPRequest()
{
	if (requestedurl) {
		free(requestedurl);
		requestedurl = NULL;
	}
	if (HTTPMethod )
	{
		free(HTTPMethod);
		HTTPMethod = NULL;
	}
	if (Data) {
		free(Data);
		Data = NULL;
	}
	DataSize = 0;
	BinaryData = 0;

}
/*******************************************************************************************************/
HTTPSTR HTTPRequest::GetRequestedURL()
{
	if (requestedurl) return ( requestedurl );
	const HTTPCHAR *p = GetHeaders();
	int len=0;
	if (p)
	{		
		while ( (*p) && (*p!=_T(' ')))  p++;
		p++;
		HTTPCHAR *q=(HTTPCHAR *)p;
		while (*q)
		{
			if ( (*q==_T(' ')) || (*q==_T('?')) || (*q==_T('&')) || (*q==_T('\r')) || (*q==_T('\n')) )
			break;
			len++; 
			q++;
		}
	}
	requestedurl = (HTTPCHAR*) malloc((len+1)*sizeof(HTTPCHAR));
	memcpy(requestedurl,p,len*sizeof(HTTPCHAR));
	requestedurl[len]=0;
	return(requestedurl);
}
/*******************************************************************************************************/
HTTPCHAR *HTTPRequest::GetHTTPMethod()
{
	if (HTTPMethod) return(HTTPMethod);
	if ( (GetHeaders()) && (HeaderSize>12) )
	{
		int len=0;
		HTTPCHAR *p=(HTTPCHAR *)GetHeaders();
		while (*p!=_T(' '))
		{
			p++;
			len++;
		}
		if (!len) return ( NULL );
		HTTPMethod=(HTTPCHAR*)malloc((len+1)*sizeof(HTTPCHAR));
		memcpy(HTTPMethod,GetHeaders(),len*sizeof(HTTPCHAR));
		HTTPMethod[len]=_T('\0');
		return(HTTPMethod);
	} else {
		return(NULL);
	}

}

/*******************************************************************************************************/
HTTPSTR HTTPRequest::GetData(void)
{
	return(Data);
}
/*******************************************************************************************************/
size_t HTTPRequest::GetDataSize(void)
{
	return(DataSize);
}
/*******************************************************************************************************/
void HTTPRequest::SetData(HTTPCHAR *lpData)
{
	Data = lpData;
}
/*******************************************************************************************************/
#ifdef _UNICODE
void HTTPRequest::SetData(char *lpData)
{
	Data = lpData;
	BinaryData = TRUE;
}
#endif

/*******************************************************************************************************/
void HTTPRequest::SetDataSize(size_t datasize)
{
	DataSize = datasize;
}
/*******************************************************************************************************/

