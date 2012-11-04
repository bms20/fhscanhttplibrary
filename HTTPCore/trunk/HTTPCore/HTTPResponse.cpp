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
#include "HTTPResponse.h"

HTTPResponse::HTTPResponse() {
	Data = NULL;
	DataW = NULL;
	DataSize = 0;
	HTTPIOMappingData = NULL;
	StatusCode = 0;

}

//-----------------------------------------------------------------------------
 HTTPResponse::~HTTPResponse()
 {
 if (HTTPIOMappingData)
 {
 if (HTTPIOMappingData->IsAssigned())
 {
 if (HTTPIOMappingData->GetMappingData() != (HTTPCHAR*)Data)
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
 if (DataW) {
 free(DataW);
 DataW = NULL;
 }
 Data = NULL;
 DataSize = 0;
 StatusCode = 0;

 }

//-----------------------------------------------------------------------------

unsigned short HTTPResponse::GetStatus() {
	if (StatusCode)
		return (StatusCode);
	if ((GetHeaders()) && (GetHeaderSize() > 12)) {
		HTTPCHAR tmp[4];
		memcpy(tmp, GetHeaders() + 9, 3*sizeof(HTTPCHAR));
		tmp[3] = 0;
		StatusCode = _tstoi(tmp);
#ifdef _DBG_
		if (StatusCode == 0) {
			_tprintf(_T("HTTP Protocol Error - Invalid HTTP header data\n"));
		}
#endif
	}
	return (StatusCode);
}
//-----------------------------------------------------------------------------
 void HTTPResponse::UpdateAndReplaceFileMappingData(HTTPIOMapping *newFileMapping)
 {
 if (HTTPIOMappingData)
 {
 if (Data == (char*)HTTPIOMappingData->GetMappingData())
 { /* previous filemapping existed , remove the filemapping however do not interact with memory */
Data = NULL;
DataSize = 0;
} delete HTTPIOMappingData;
HTTPIOMappingData = NULL;
}
else {
if (Data) {
free(Data);
Data = NULL;
}
DataSize = 0;
}

if (newFileMapping) {
HTTPIOMappingData = newFileMapping;
Data = (char*) HTTPIOMappingData->GetMappingData();
if (Data == NULL) {
delete HTTPIOMappingData;
HTTPIOMappingData = NULL;
}
else {
DataSize = HTTPIOMappingData->GetMappingSize();
}
}
}

//-----------------------------------------------------------------------------
 char* HTTPResponse::Datastrstr(HTTPCHAR* searchdata)
 {
 if ((Data) && (DataSize))
 {
 //return(strstr(Data,searchdata));
 //TODO 7

 }
 return(NULL);
 }
//-----------------------------------------------------------------------------
void HTTPResponse::SetData(void *lpData) {
// Data = (HTTPCHAR*)lpData;

}

//-----------------------------------------------------------------------------
 void HTTPResponse::SetData(void *lpData, size_t Datalength)
 {
 Data = (char*)malloc((Datalength+1));
 if (Data) {
 memcpy(Data,lpData,Datalength);
 Data[Datalength]=(HTTPCHAR)0;
 DataSize = Datalength;
 } else {
 DataSize = 0;
 }
 }


//-----------------------------------------------------------------------------
void HTTPResponse::SetDataSize(size_t datasize) {
DataSize = datasize;
}
//-----------------------------------------------------------------------------
 HTTPSTR HTTPResponse::GetServerVersion()
 {
 HTTPCHAR *server=NULL;
 if ((Header) && (HeaderSize) )
 {
 if (server) {
 free(server);
 //TODO: Revisar que es correcto
 }
 server = GetHeaderValue(_T("Server: "),0);
 }
 return( server ? server :_tcsdup(_T("HTTP/1.0")) );
 }
//-----------------------------------------------------------------------------
// Automatic conversion to UTF8
#ifdef UNICODE

HTTPCHAR *HTTPResponse::GetDataW(void) {

if (this->DataW != NULL) {
return (this->DataW);
}
/* Unicode conversion */
int len = MultiByteToWideChar(CP_UTF8, 0, Data, -1, NULL, 0);
if (len) {
// _tprintf(_T("Source Buffer: %i bytes - Destination %i bytes\n"),length,HeaderSize);
DataW = (wchar_t*)malloc((len + 1)*sizeof(HTTPCHAR));
if (DataW) /* Validate allocation */ {
MultiByteToWideChar(CP_UTF8, 0, Data, DataSize, DataW, len);
DataW[len - 1] = 0;
}
}
return (this->DataW);
}
#endif
