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
#include "FileMapping.h"
#include "HTTPHANDLE.h"


/*!\STRUCT PREQUEST
  \brief This struct handles information related to and http response and includes information about client request, server response, url, server version .returned by an HTTP Server
*/
typedef struct  prequest {
	HTTPCHAR hostname[256];
   /*!< hostname of the server. This is related to the vhost parameter. If no vhost is specified, hostname contains the ip address. */
   int ip;
   /*!< remote HTTP ip address. */
   int port;
   /*!< remote HTTP port. This value is obtained from the InitHTTPConnectionHandle() */
   int NeedSSL;
   /*!< Boolean value. If this parameter is 1 then the connection is handled by openssl otherwise is just a tcp connection */
   HTTPSTR url;
   /*!< path to the file or directory requested */
   HTTPSTR Parameters;
   /*!< Request Parameters */
   httpdata* request;
   /*!< Information related to the HTTP Request. This struct contains both client headers and postdata */
   httpdata* response;
   /*!< Information related to the HTTP response. This struct contains both server headers and data */
   HTTPSTR server;
   /*!< pointer to a string that contains the server banner from the remote http server */
   HTTPCHAR Method[20];
   /*!< HTTP Verb used */
   unsigned int status;
   /*!< status code returned by the HTTP server. Example: "200", for an STATUS OK response. */
   HTTPSTR ContentType;
   /*!< Response Content-Type */
public:
   prequest();
   ~prequest();
   int IsValidHTTPResponse(void);
   int HasResponseHeader(void);
   int HasResponseData(void);
} *PREQUEST;

/*!\struct HTTP_DATA
  \brief An HTTP_DATA struct stores the information generated with an HTTP request or an HTTP response.\n
  If the data is related to an HTTP request, this struct will store the browser request headers and optional Post data.\n
  If the data is related to an HTTP response, this struct will store the HTTP server response headers and HTTP data.
*/

struct httpdata {
private:
	HTTPIOMapping *HTTPIOMappingData;
	int nComments;
	char **Comments;
	int nUrlCrawled;
	char **UrlCrawled;
	char **linktagtype;
	
public:
	HTTPSTR Header;
    /*!< Pointer to a null terminated string that stores the HTTP Headers.\n 
	The data stored under this parameter can b*/	
	unsigned int HeaderSize;
    /*!< Size of the HTTP Headers. */
	HTTPSTR Data;
    /*!< Pointer to a null terminated string that stores the HTTP Data. */
	unsigned int DataSize;
    /*!< Size of the HTTP Data. */

	/* Initialization */
	httpdata();
	httpdata(const char *header);
	httpdata(const char *header, int headersize);
	httpdata(const char *header, const char *lpPostData);
	httpdata(const char *header,unsigned int headersize, const char *lpPostData,unsigned int PostDataSize);	
	void InitHTTPData(const char *header);
	void InitHTTPData(const char *header, int headersize);
	void InitHTTPData(const char *header, const char *lpPostData);
	void InitHTTPData(const char *header,unsigned int headersize, const char *lpPostData,unsigned int PostDataSize);
	~httpdata();

	/* Header manipulation */
	char *GetHeaderValue(const char *value,int n);
	char *GetHeaderValueByID(unsigned int id);
	char *AddHeader(const char *Header);
	char *RemoveHeader(const char *Header);	
	

	/* Information gathering */
	char			*GetServerVersion();
	int 			 GetStatus();
	char			*GetRequestedURL();
	char			*GetHTTPMethod();
	enum AuthenticationType GetSupportedAuthentication(void);

	void UpdateAndReplaceFileMappingData(HTTPIOMapping *newFileMapping);

	/* Spider */
	int GetnComments();
	int AddComment(char *lpComment);
	char *GetComment(int i);
	int GetnUrlCrawled();
	int AddUrlCrawled(char *lpComment, char *tagtype);
	char *GetUrlCrawled(int i);
	char *GettagCrawled(int i);

	/* Misc Functions */
	char *Datastrstr  (const char *searchdata);
	char *Headerstrstr(const char *searchdata);
};

typedef int HTTPHANDLE;


#endif
