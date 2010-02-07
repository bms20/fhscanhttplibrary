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
#include "HTTPResponse.h"



HTTPResponse::HTTPResponse()
{
	Data = NULL;
	DataSize = 0;
	HTTPIOMappingData = NULL;
	StatusCode = 0;

}
/*******************************************************************************************************/
void HTTPResponse::InitHTTPResponse(HTTPCHAR *HTTPHeaders, HTTPCHAR *HTTPData)
{
	InitHTTPHeaders(HTTPHeaders);
	Data = _tcsdup(HTTPData);
	DataSize = _tcslen(HTTPData);
}
/*******************************************************************************************************/
void HTTPResponse::InitHTTPResponse(HTTPCHAR *HTTPHeaders, void* HTTPData, size_t HTTPDataSize)
{
	InitHTTPHeaders(HTTPHeaders);
	Data = (HTTPCHAR*) malloc(HTTPDataSize);
	memcpy(Data,HTTPData,HTTPDataSize*sizeof(HTTPCHAR));
	DataSize = HTTPDataSize;
//	BinaryData = 1;
}
/*******************************************************************************************************/
void HTTPResponse::InitHTTPResponse(HTTPCHAR *HTTPHeaders, size_t HTTPHeaderSize, void* HTTPData, size_t HTTPDataSize)
{
	Header = (HTTPCHAR*)malloc(HTTPHeaderSize+1);
	memcpy(Header,HTTPHeaders,HTTPHeaderSize*sizeof(HTTPCHAR));
	Header[HTTPHeaderSize]=0;
	HeaderSize = HTTPHeaderSize;

	Data = (HTTPCHAR*)malloc(HTTPDataSize);
	memcpy(Data,HTTPData,HTTPDataSize*sizeof(HTTPCHAR));
	DataSize = HTTPDataSize;
//	BinaryData = 1;

}
/*******************************************************************************************************/

/*******************************************************************************************************/
#ifdef UNICODE	
void HTTPResponse::InitHTTPResponseA(char *lpBuffer,size_t HTTPHeaderSize, void *HTTPData, size_t HTTPDataSize)
{
/*char *tmpHeader = (char*)malloc(HTTPHeaderSize+1);
memcpy(tmpHeader,lpBuffer,HTTPHeaderSize);
tmpHeader[HTTPHeaderSize]=0;
*/
int ret = MultiByteToWideChar(CP_UTF8, 0, lpBuffer, HTTPHeaderSize, NULL, 0);
_tprintf(_T("Tenemos %i bytes - Necesitamos %i bytes\n"),HTTPHeaderSize,ret);
Header = (wchar_t*)malloc((ret +1)*sizeof(HTTPCHAR));
HeaderSize = ret;
ret = MultiByteToWideChar(CP_UTF8, 0, lpBuffer, HTTPHeaderSize, Header, ret);
Header[HeaderSize]=0;
if (HTTPDataSize)
{
	printf("TODO");
	getchar();
	/*
	Data = malloc(HTTPDataSize);
	memcpy(Data,HTTPData,HTTPDataSize);
	DataSize = HTTPDataSize;
*/
//	BinaryData = 1;
}
}
#endif
/*******************************************************************************************************/
HTTPResponse::~HTTPResponse()
{
		if (HTTPIOMappingData)
		{
			if (HTTPIOMappingData->IsAssigned())
			{
				if (HTTPIOMappingData->GetMappingData() != Data)
				{
					if (Data)	free(Data);
				} 
				delete HTTPIOMappingData;
			} else 
			{
				if (Data)	free(Data);
			}
		} else {
			if (Data)	free(Data);
		}
		Data = NULL;
		DataSize = 0;
		StatusCode = 0;

}
/*******************************************************************************************************/
int HTTPResponse::GetStatus()
{
	if (StatusCode) return(StatusCode);
	if ( (GetHeaders()) && (GetHeaderSize()>12) )
	{
		HTTPCHAR tmp[4];
		//HTTP/1.0 200 Ok
//		_tprintf(_T("%s\n"),GetHeaders());

		memcpy(tmp,GetHeaders()+9,3*sizeof(HTTPCHAR));
		tmp[3]=0;
		StatusCode = _tstoi(tmp);
#ifdef _DBG_
		if (StatusCode ==0)
		{
			_tprintf(_T("HTTP Protocol Error - Invalid HTTP header data\n"));
		}
#endif
	}
	return(StatusCode);
}
/*******************************************************************************************************/
void HTTPResponse::UpdateAndReplaceFileMappingData(HTTPIOMapping *newFileMapping)
{
	if (HTTPIOMappingData)
	{
		if (Data == HTTPIOMappingData->GetMappingData())
		{ /* previous filemapping existed , remove the filemapping however do not interact with memory*/
			Data = NULL;
			DataSize = 0;
		}
	   delete HTTPIOMappingData;
	   HTTPIOMappingData = NULL;
	} else {
		if (Data) {
			free(Data);
			Data = NULL;
        }
		DataSize = 0;
	}
	
	if (newFileMapping)
	{
		HTTPIOMappingData = newFileMapping;
	 	Data = HTTPIOMappingData->GetMappingData();
		if (Data == NULL)
		{
			delete HTTPIOMappingData;
			HTTPIOMappingData = NULL;
		} else
		{
			DataSize = HTTPIOMappingData->GetMappingSize();
		}
	}
}
/*******************************************************************************************************/
HTTPCHAR* HTTPResponse::Datastrstr(HTTPCHAR* searchdata)
{
	if ((Data) && (DataSize))
	{
		return(_tcsstr(Data,searchdata));
	}
	return(NULL);
}
/*******************************************************************************************************/
void HTTPResponse::SetData(void *lpData)
{
	Data = (HTTPCHAR*)lpData;
}
/*******************************************************************************************************/
void HTTPResponse::SetDataSize(size_t datasize)
{
	DataSize = datasize;
}
/*******************************************************************************************************/
HTTPSTR HTTPResponse::GetServerVersion()
{
	HTTPCHAR *server=NULL;
	if ((Header) && (HeaderSize) )
	{
		server = GetHeaderValue(_T("Server: "),0);
	}
	return( server ? server :_tcsdup(_T("HTTP/1.0")) );
}
/*******************************************************************************************************/
