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
/** \file ConnectionHandling.h
* Fast HTTP Auth Scanner - HTTP Engine v1.4.
* ..
* \author Andres Tarasco Acuna - http://www.tarasco.org
*/
#ifndef __CONNECTIONHANDLING_H__
#define __CONNECTIONHANDLING_H__

#include "Build.h"
// #include "Threading.h"
#include "HTTPHANDLE.h"
#include "HTTP.h"
#include "FileMapping.h"
#include "SSLModule.h"
//#include <time.h>

#ifndef __WIN32__RELEASE__
#define FILETIME time_t
#endif

#define KEYFILE		"server.pem"
#define CA_LIST		"root.pem"
#define PASSWORD	"password"
#define DHFILE		"dh1024.pem"

#define HTTP_READ_TIMEOUT		10
#define HTTP_CONN_TIMEOUT		10
#define BUFFSIZE                4096 /*default read size buffer */
#define MAX_CHECK_TIME_FOR_BW_UTILIZATION  200
#define HTTP_CONN_TIMEOUT 10
#define HTTP_READ_TIMEOUT 10
#define HTTP_MAX_CONNECTIONS 100

#define MAX_CHUNK_LENGTH						12
#define ERROR_MORE_DATA_NEEDED 					-1
#define CHUNK_INSUFFICIENT_SIZE                 -1
#define CHUNK_ERROR                             -2

#define ERROR_PARSING_DATA     					0xFFFFFF

#define TARGET_FREE   							0
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

class ConnectionHandling : public SSLModule {

	HTTPCHAR HACK_TargetDNS[256];
	HTTPSTR HACK_lpProxyHost;

	//long m_target;
	//HTTPCHAR targetDNS[256];
	unsigned short port;
	int SSLRequired; /* Signals if the connection is against an SSL service */
	int ConnectionAgainstProxy; /* Signals if HTTP Proxy is enabled */

	SSL_CTX * ctx;
	SSL * ssl; /* Signals if the ssl connection have already been initialized */
	BIO *bio_err;

	unsigned int datasock; /* connection socket */
#ifdef IPV6
	struct sockaddr_in6 webserver;
#else
	struct sockaddr_in webserver;
#endif
	unsigned int NumberOfRequests;
	/* Number of HTTP requests performed since connected */
	unsigned int InputOutputOperation;
	/* Signals if the connection is currently trying to connect to a remote host */

	unsigned int BwLimit; /* Bandwith limit */
	unsigned int DownloadLimit; /* Download size limit */
#ifdef __WIN32__RELEASE__
	int ThreadID; /* Thread Identifier of the calling process */
#else
	pthread_t ThreadID;
#endif
	FILETIME LastConnectionActivity;
	/* Called externally by CleanConnectionTable() */

	char * HTTPServerResponseBuffer;
	unsigned int HTTPServerResponseSize;
	char * HTTPProxyClientRequestBuffer;
	unsigned int HTTPProxyClientRequestSize;
	int pending;
	/* Signals if there is cached data available for reading under an SSL connection */
	BOOL ConnectionClose;

	int LimitIOBandwidth(unsigned long ChunkSize, struct timeval LastTime,
	struct timeval CurrentTime, int MAX_BW_LIMIT);
	int StablishConnection(void);
	int InitSSLConnection();
	int ReadBytes(char *buf, size_t bufsize, struct timeval *tv);
	long ReadChunkNumber(char *encodedData, size_t encodedlen, char *chunkcode);
	int SendBufferToProxyClient(class ConnectionHandling *ProxyClientConnection,char *buf, int read_size);
	HTTPResponse *ReadHTTPResponseData
		(class ConnectionHandling *ProxyClientConnection, HTTPRequest* request, int *ErrorCode);
	void CloseSocket(void);
	int SendData(char *data, size_t len);

public:
	ConnectionHandling();
	~ConnectionHandling();

	int Connectionid;
	class Threading IoOperationLock; // support pipelining

	int InitializeConnection(class HTTPAPIHANDLE *HTTPHandle);
	void Disconnect(int level);
	HTTPRequest *ReadHTTPProxyRequestData();
	int SendHttpRequest(HTTPRequest* request);
	int SendHttpResponse(HTTPResponse *response);

	HTTPResponse *SendAndReadHTTPData(class HTTPAPIHANDLE *HTTPHandle, HTTPRequest *request);

	void Acceptdatasock(SOCKET ListenSocket);
	HTTPCHAR* GettargetDNS(void);
	//long GetTarget(void);
	int GetPort(void);
	int GetThreadID(void);
	unsigned int Getio(void);
	void Setio(unsigned int value);
	int GetConnectionAgainstProxy(void);
	void UpdateLastConnectionActivityTime(void);
	FILETIME GetLastConnectionActivityTime(void);
	void * IsSSLInitialized(void);
	void SetBioErr(void *bio);
	int SetCTX(void *proxyctx);
};
#endif
