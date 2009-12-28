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
#ifndef __HTTPDATA_H__
#define __HTTPDATA_H__
//#include "FileMapping.h"
//#include "HTTPHANDLE.h"
//#include "HTTPHeaders.h"




#if 0

/*!\struct HTTP_DATA
  \brief An HTTP_DATA struct stores the information generated with an HTTP request or an HTTP response.\n
  If the data is related to an HTTP request, this struct will store the browser request headers and optional Post data.\n
  If the data is related to an HTTP response, this struct will store the HTTP server response headers and HTTP data.
*/

class httpdata : public HTTPHeaders {
private:
	HTTPIOMapping *HTTPIOMappingData;
	int nComments;
	HTTPCHAR **Comments;
	int nUrlCrawled;
	HTTPCHAR **UrlCrawled;
	HTTPCHAR **linktagtype;
	
public:
	
	HTTPSTR Data;
    /*!< Pointer to a null terminated string that stores the HTTP Data. */
	size_t DataSize;
    /*!< Size of the HTTP Data. */

	/* Initialization */
	httpdata();
	httpdata(HTTPCSTR header);
	httpdata(HTTPCSTR header, size_t headersize);
	httpdata(HTTPCSTR header, HTTPCSTR lpPostData);
	httpdata(HTTPCSTR header,size_t headersize, HTTPCSTR lpPostData,size_t  PostDataSize);	
	void InitHTTPData(HTTPCSTR header);
	void InitHTTPData(HTTPCSTR header, size_t headersize);
	void InitHTTPData(HTTPCSTR header, HTTPCSTR lpPostData);
	void InitHTTPData(HTTPCSTR header,size_t  headersize, HTTPCSTR lpPostData,size_t  PostDataSize);
	~httpdata();
#ifdef UNICODE
/* Need extra methods */
	void InitHTTPDataA(char* header,size_t headersize, char* lpPostData,size_t PostDataSize);
	//httpdata(char* header, size_t  headersize);
#endif

	/* Header manipulation */
	HTTPSTR GetHeaderValue(HTTPCSTR value,int n);
	HTTPSTR GetHeaderValueByID(unsigned int id);
	HTTPSTR AddHeader(HTTPCSTR Header);
	HTTPSTR RemoveHeader(HTTPCSTR Header);	
	


	

	/* Spider */
	int GetnComments();
	int AddComment(HTTPCHAR *lpComment);
	HTTPCHAR *GetComment(int i);
	int GetnUrlCrawled();
	int AddUrlCrawled(HTTPCHAR *lpComment, HTTPCHAR *tagtype);
	HTTPCHAR *GetUrlCrawled(int i);
	HTTPCHAR *GettagCrawled(int i);

	/* Misc Functions */
	HTTPSTR Datastrstr  (HTTPCSTR searchdata);
	HTTPSTR Headerstrstr(HTTPCSTR searchdata);
};
#endif



#endif
