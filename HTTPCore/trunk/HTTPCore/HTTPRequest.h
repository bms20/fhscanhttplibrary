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
#ifndef __HTTP_REQUEST_H_
#define __HTTP_REQUEST_H_
#include "HTTPHANDLE.h"
#include "HTTPHeaders.h"

class HTTPRequest : public HTTPHeaders {
private:
	HTTPCHAR *requestedurl;
	HTTPCHAR *HTTPMethod;
#ifdef _UNICODE
//	char *DataA; /* Store raw data */
#endif

public:
	HTTPCHAR* PostData;
	/* !< Pointer to a null terminated HTTPCHAR string that stores the HTTP Data. */
	size_t DataSize;
	/* !< Size of the HTTP Data. */
//	BOOL BinaryData;

	HTTPRequest();
	~HTTPRequest();
	void SetData(HTTPCHAR *lpData);
	void SetData(HTTPCHAR *lpData, size_t Datalength);
#ifdef _UNICODE
	void SetData(char *lpData);
	void SetData(char *lpData, size_t Datalength);
//	char* GetDataA(void);
#endif
	HTTPSTR GetData(void);
	size_t GetDataSize(void);

	/* Information gathering */
	HTTPSTR GetRequestedURL();
	HTTPSTR GetHTTPMethod();
};
#endif
