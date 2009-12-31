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
#ifndef __HTTP_REQUEST_H_
#define __HTTP_REQUEST_H_
#include "HTTPHANDLE.h"
#include "HTTPHeaders.h"


class HTTPRequest : public HTTPHeaders 
{
private:
	HTTPCHAR *requestedurl;
	HTTPCHAR *HTTPMethod;
public:
	HTTPCHAR* Data;
    /*!< Pointer to a null terminated HTTPCHAR string that stores the HTTP Data. */
	size_t DataSize;
    /*!< Size of the HTTP Data. */
	BOOL BinaryData;

	HTTPRequest();
	~HTTPRequest();
	void InitHTTPRequest(HTTPCHAR *HTTPHeaders);
	void InitHTTPRequest(HTTPCHAR *HTTPHeaders, HTTPCHAR *HTTPData);
	void InitHTTPRequest(HTTPCHAR *HTTPHeaders, HTTPCHAR* HTTPData, size_t HTTPDataSize);
	void InitHTTPRequest(HTTPCHAR *HTTPHeaders,size_t HTTPHeaderSize, HTTPCHAR* HTTPData, size_t HTTPDataSize);
#ifdef UNICODE	
	void InitHTTPRequestA(char *lpBuffer,size_t HTTPHeaderSize,void *HTTPData, size_t HTTPDataSize);
#endif

	/* Information gathering */
	HTTPSTR GetRequestedURL();
	HTTPSTR GetHTTPMethod();	
	HTTPSTR GetData(void);
	size_t GetDataSize(void);
void SetData(HTTPCHAR *lpData);
#ifdef _UNICODE
void SetData(char *lpData);
#endif
void SetDataSize(size_t datasize);

};
#endif