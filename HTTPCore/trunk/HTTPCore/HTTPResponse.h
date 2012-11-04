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
#ifndef __HTTP_RESPONSE_H_
#define __HTTP_RESPONSE_H_
#include "FileMapping.h"
#include "HTTPHANDLE.h"
#include "HTTPHeaders.h"

class HTTPResponse : public HTTPHeaders {
private:
	HTTPIOMapping *HTTPIOMappingData;
	unsigned short StatusCode;

public:
	/* !< Pointer to a null terminated string that stores the HTTP Response Data. */
	char* Data;
	/* !< Size of the HTTP Data. */
	size_t DataSize;

	HTTPCHAR *DataW;

#ifdef _UNICODE
	int BinaryData;
#endif

	HTTPResponse();
	~HTTPResponse();

	HTTPSTR GetServerVersion();

	unsigned short GetStatus();
	void UpdateAndReplaceFileMappingData(HTTPIOMapping *newFileMapping);

	char* Datastrstr(HTTPCHAR* searchdata);

	void* GetData(void) { return (Data); }

	HTTPCHAR *GetDataW(void);
	size_t GetDataSize(void) { return (DataSize); }


	void SetData(void *lpData);
	void SetData(void *lpData, size_t Datalength);
	void SetDataSize(size_t datasize);

};
#endif
