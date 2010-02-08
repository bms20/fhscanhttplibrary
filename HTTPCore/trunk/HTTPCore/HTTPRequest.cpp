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
#ifdef _UNICODE
	DataA = NULL;
#endif
	DataSize = 0;
	requestedurl = NULL;
	HTTPMethod = NULL;
	BinaryData = 0;
}
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
#ifdef _UNICODE
	if (DataA)
	{
		free(DataA);
		DataA = NULL;
	}

#endif
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
void HTTPRequest::SetData(HTTPCHAR *lpData, size_t DataLength)
{
	if (Data)
	{
		free(Data);
		Data = NULL;
		DataSize = 0;
	}
	if (lpData)
	{
		Data = (HTTPCHAR*)malloc((DataLength+1)*sizeof(HTTPCHAR));
		if (Data)
		{
			memcpy(Data,lpData,DataLength*sizeof(HTTPCHAR));
			Data[DataLength]=0;
			DataSize = DataLength;
			BinaryData = 0;
		}
	}
}
/*******************************************************************************************************/
void HTTPRequest::SetData(HTTPCHAR *lpData)
{
	if (lpData)
	{
		SetData(lpData,_tcslen(lpData));
	} else
	{
		SetData((HTTPCHAR*)NULL,0);
	} 
}
/*******************************************************************************************************/
#ifdef _UNICODE
void HTTPRequest::SetData(char *lpData, size_t DataLength)
{
	if (Data)
	{
		free(Data);
		Data = NULL;
		DataSize = 0;
	}
	if (lpData)
	{
		if (strlen(lpData) == DataLength) /* No binary data */
		{
			/* Unicode conversion */
			DataSize = MultiByteToWideChar(CP_UTF8, 0, lpData, DataLength, NULL, 0);
			if (DataSize)
			{
				_tprintf(_T("Source Buffer: %i bytes - Destination %i bytes\n"),DataLength,DataSize);
				Data = (wchar_t*)malloc((DataSize +1)*sizeof(HTTPCHAR));
				if (Data) 
				{
					/* Validate allocation */
					MultiByteToWideChar(CP_UTF8, 0, lpData, DataLength, Data, DataSize);
					Data[DataSize]=0;
					return;
				} else {
					/* Memory Allocation error */
					DataSize = 0;
				}
			} else {
				/* For some reason utf-8 conversion failed */
				BinaryData = 1;
			}
		} else {
			BinaryData  = 1;
		}
		/* Also copy the data, to be send as is */
		DataA = (char*)malloc(DataLength+1);
		DataSize = DataLength;
		memcpy(DataA,lpData,DataLength);
		Data[DataSize]=0;

	}
}
/*******************************************************************************************************/
void HTTPRequest::SetData(char *lpData)
{
	if (lpData)
	{
		SetData(lpData,strlen(lpData));
	} else 
	{
		SetData((char*)NULL,0);
	} 
}
/*******************************************************************************************************/
char *HTTPRequest::GetDataA(void)
{
	return ( DataA );	
}
#endif

/*******************************************************************************************************/