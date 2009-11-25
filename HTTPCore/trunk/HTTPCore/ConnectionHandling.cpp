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
#include "ConnectionHandling.h"
#include "misc.h"
#include <stdio.h>
#include <stdlib.h>



/*******************************************************************************************************/
ConnectionHandling::ConnectionHandling()
{
	target = 0;
	*targetDNS = 0;
	port = 0;
	datasock = 0;
	ctx = NULL;
	ssl = NULL;
	bio_err = NULL;
	NeedSSL = 0;

#ifdef __WIN32__RELEASE__
	LastConnectionActivity.dwHighDateTime = 0;
	LastConnectionActivity.dwLowDateTime = 0;
#else
	LastConnectionActivity = 0;
#endif
	NumberOfRequests = 0;
	InputOutputOperation = 0;
	Connectionid = 0;
	BwLimit = 0;
	DownloadLimit= 0;
	ThreadID = 0;
	ConnectionAgainstProxy = 0;

	HTTPServerResponseBuffer=NULL;
	HTTPServerResponseSize=0;

	HTTPProxyClientRequestBuffer=NULL;
	HTTPProxyClientRequestSize = 0;

}
/*******************************************************************************************************/
ConnectionHandling::~ConnectionHandling()
{
	Disconnect(1);
}
/*******************************************************************************************************/
int ConnectionHandling::StablishConnection(void)
{
	fd_set fds, fderr;
	struct timeval tv;
	pending = 0;
	NumberOfRequests = 0;
	datasock = (int) socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	webserver.sin_family = AF_INET;
	webserver.sin_addr.s_addr = target;//inet_addr(target);
	webserver.sin_port = htons(port);

#ifdef __WIN32__RELEASE__
	u_long tmp=1;
	ioctlsocket( datasock, FIONBIO, &tmp);
#else
	int tmp = 1;
	ioctl(datasock, FIONBIO, (char *) &tmp);
#endif	
	connect(datasock, (struct sockaddr *) &webserver, sizeof(webserver));
	tv.tv_sec = HTTP_CONN_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_ZERO(&fderr);
	FD_SET(datasock, &fds);
	FD_SET(datasock, &fderr);
	if (select((int) datasock + 1, NULL,&fds, NULL,&tv) <= 0)
	{
#ifdef _DBG_
		printf("StablishConnection::Unable to connect Conexion %i to  (%s):%i\n",id,inet_ntoa(webserver.sin_addr),port);
#endif
		closesocket(datasock);
		datasock = 0;
		return (0);
	}

#ifdef _DBG_
	printf("StablishConnection: Socket CONNECTED Conexion %i (%s:%i)\n",id,inet_ntoa(webserver.sin_addr),port);

#endif
	UpdateLastConnectionActivityTime();

	return (1);
}
/*******************************************************************************************************/
int ConnectionHandling::InitializeConnection(class HTTPAPIHANDLE *HTTPHandle)
{
	if (datasock==0)
	{
		target=HTTPHandle->GetTarget();		
		NeedSSL = HTTPHandle->IsSSLNeeded();

		if (HTTPHandle->ProxyEnabled())
		{			
			port=atoi(HTTPHandle->GetHTTPConfig(ConfigProxyPort));
			ConnectionAgainstProxy=1;
		} else
		{
			port=HTTPHandle->GetPort();
			ConnectionAgainstProxy=0;			
		}	

		int ret = StablishConnection();
		if (!ret)
		{
			target = TARGET_FREE;
			return(0);
		}
		strcpy(this->targetDNS, HTTPHandle->GettargetDNS());
		#ifdef _DBG_
		printf("Connection stablished against %s\n",this->targetDNS);
		#endif
		BwLimit=HTTPHandle->GetDownloadBwLimit();
		DownloadLimit=HTTPHandle->GetDownloadLimit();
		ThreadID = HTTPHandle->GetThreadID();
		HTTPHandle->SetConnection((void*)this);
	}
	return(1);
}
/*******************************************************************************************************/
void ConnectionHandling::Disconnect(int level)
{
	if (NeedSSL)
	{
		if (ssl)
		{
			SSL_SHUTDOWN(ssl);
			SSL_FREE(ssl);
		}
		if (ctx) SSL_CTX_FREE(ctx);
		ctx=NULL;
		ssl = NULL;
	}
	shutdown(datasock,2);
	closesocket(datasock);
	datasock = 0;
	NumberOfRequests=0;
	if (HTTPServerResponseBuffer)
	{
		free(HTTPServerResponseBuffer);
		HTTPServerResponseSize = 0;
	}
	if (HTTPServerResponseBuffer)
	{
		free(HTTPProxyClientRequestBuffer);
		HTTPProxyClientRequestSize = 0;
	}
	
	if (level == 1)
	{
		*targetDNS = 0;
		port = 0;
		target  = 0;
		NeedSSL = 0;
		BwLimit = 0;
		DownloadLimit = 0;
	#ifdef __WIN32__RELEASE__
		LastConnectionActivity.dwHighDateTime=0;
		LastConnectionActivity.dwLowDateTime=0;
	#else
		LastConnectionActivity=0;
	#endif
	}
}
/*******************************************************************************************************/
#define HTTP_CONNECTION_CLOSE			   0x01
#define HTTP_RECV_ERROR_CODE_NO_ERROR      0x02
#define HTTP_RECV_ERROR_CODE_NO_DATA       0x04
#define HTTP_RECV_ERROR_CODE_INVALID_DATA  0x08



int ConnectionHandling::SendHTTPRequest(httpdata* request)
{
	if ( (NeedSSL) && (!ssl) && 
		( ((NumberOfRequests==0) && (!ConnectionAgainstProxy ) ) || //First SSL Request
		(  (NumberOfRequests==1) && ( ConnectionAgainstProxy ) ) ) )   //Seccond HTTP Request against the HTTP Proxy Host
	{
		if (! InitSSLConnection()) return(0);
	}

	if (ssl) 
	{
		int err=SSL_WRITE(ssl, request->Header, (int)request->HeaderSize);
		if (err>0)
		{
			if (request->DataSize)
			{
				err=SSL_WRITE(ssl, request->Data, (int)request->DataSize);
			}
		}
		if (err <=0)
		{
#ifdef _DBG_
			printf("SSL_WRITE ERROR1: %s:%i\n",targetDNS,port);
#endif
			return(0);
		}
	} else
	{

		int err = send(datasock, request->Header, (int)request->HeaderSize, 0);
		if (err > 0)
		{
			if (request->DataSize)
			{
				err = send(datasock, request->Data, (int)request->DataSize, 0);
			}
		}
		if (err <= 0)
		{
#ifdef _DBG_
			printf("Send() ERROR1: %s:%i\n",targetDNS,port);
#endif
			return (0);
		}

	}

	UpdateLastConnectionActivityTime();
	return (1);
}

/**********************************************************/
httpdata* ConnectionHandling::SendAndReadHTTPData(class HTTPAPIHANDLE *HTTPHandle,httpdata *request)
{
	IoOperationLock.LockMutex();
	httpdata *response = NULL;
	int ret = InitializeConnection(HTTPHandle);
	if (ret)
	{
		ret = SendHTTPRequest(request);
		if (ret) 
		{
			int ErrorCode = 0;
			int n = NumberOfRequests;
			response = ReadHTTPResponseData((ConnectionHandling*)HTTPHandle->GetClientConnection(),request,&ErrorCode);				
			if (ErrorCode & HTTP_CONNECTION_CLOSE) 
			{
					/* The client signaled to close the connection */
					Disconnect(0); 
			}
			if ( (ErrorCode & HTTP_RECV_ERROR_CODE_NO_DATA) || (ErrorCode & HTTP_RECV_ERROR_CODE_INVALID_DATA) )
			{
				if (n) 
				{
					/* Our data is corrupted/Invalid/Empty. Retry the request */
					IoOperationLock.UnLockMutex();
					return SendAndReadHTTPData(HTTPHandle,request);
				}
			}
			if (ErrorCode & HTTP_RECV_ERROR_CODE_NO_ERROR)
			{
					/* Operation succed */
					NumberOfRequests++;
			}
		}
	}
	IoOperationLock.UnLockMutex();
	return(response);
}
/**********************************************************/
int ConnectionHandling::ReadBytes(char *buf, size_t bufSize, struct timeval *tv)
{
	fd_set fdread, fds, fderr;     /* descriptors to be signaled by select events */
	UpdateLastConnectionActivityTime();
	if (HTTPServerResponseBuffer)
	{
		/* Reuse previously readed data */
		memcpy(buf,HTTPServerResponseBuffer,HTTPServerResponseSize);
		free(HTTPServerResponseBuffer);
		HTTPServerResponseBuffer = NULL;
		HTTPServerResponseSize = 0;
		return  HTTPServerResponseSize;
	} 
	/* Wait for readable data at the socket */
	FD_ZERO(&fds);
	FD_SET(datasock, &fds);
	FD_ZERO(&fderr);
	FD_SET(datasock, &fderr);
	FD_ZERO(&fdread);
	FD_SET(datasock, &fdread);

	int read_size = 0;

	if (pending) 
	{
		if (ssl) 
		{
			read_size=SSL_READ(ssl, buf, bufSize );
			pending= SSL_PENDING(ssl);
		}
		return (read_size);
	}

	int i = select((int) datasock + 1, &fdread, NULL,&fderr, tv);
	/* No events from the select means that connection timed out (due to network error, read timeout or maybe and http protocol error */
	if (i == 0)
	{		
		return(0);
	}

	if ( FD_ISSET(datasock, &fdread) ) 
	{
		if (ssl)
		{
			read_size=SSL_READ(ssl, buf, bufSize);
			pending= SSL_PENDING(ssl);
			SSL_GET_ERROR(ssl,read_size);
		} else
		{
			read_size = recv(datasock, buf, bufSize, 0);
		}
	}
	return(read_size);
}

/************************************************************************************************************************/

double ConnectionHandling::ReadChunkNumber(char *encodedData, size_t encodedlen, char *chunkcode)
{
	char *p;
	if (encodedlen<=2)
	{
		return(CHUNK_INSUFFICIENT_SIZE);
	}
	if (encodedlen>=MAX_CHUNK_LENGTH)
	{						
		memcpy(chunkcode,encodedData,MAX_CHUNK_LENGTH);
		chunkcode[MAX_CHUNK_LENGTH]='\0';
		p=strstr(chunkcode,"\r\n");
		if (!p)
		{
#ifdef _DBG_
			printf("Chunk encoding Error. Data chunk Format error %s\n",chunkcode);
#endif
			return (CHUNK_ERROR);
		}
	} else
	{
		memcpy(chunkcode,encodedData,encodedlen);
		chunkcode[encodedlen]='\0';
		p=strstr(chunkcode,"\r\n");
		if (!p) return CHUNK_INSUFFICIENT_SIZE; /*Chunk encoding Error. Not enought data. Waiting for next chunk*/
	}
	*p='\0';
	unsigned long chunk=strtol(chunkcode,NULL,16);
	/*Security check! */
	if (chunk == 0)
	{
		p = chunkcode;
		do {
			if (*p!='0') {
				return (CHUNK_ERROR);
			}
			p++;
		} while (*p!='\0');
	}
	return(chunk);

}
/************************************************************************************************************************/
httpdata *GetHttpHeadersFromBuffer(char *lpBuffer)
{
	size_t offset = 0;
	char *HeadersEnd = NULL;
	char *p = strstr(lpBuffer, "\r\n\r\n");
	if (p)
	{
		offset = 4;
		HeadersEnd = p;
	}
	p = strstr(lpBuffer, "\n\n"); // no rfc compliant (like d-link routers)
	if (p)
	{
		if ((!HeadersEnd) || (p < HeadersEnd))
		{
			offset = 2;
			HeadersEnd = p;
		}
	}
	if (!HeadersEnd)
	{
		return(NULL);
	}
	return ( new httpdata (lpBuffer,(HeadersEnd - lpBuffer) + offset) );
}
/************************************************************************************************************************/
int ConnectionHandling::SendBufferToProxyClient(class ConnectionHandling *ProxyClientConnection, char *buf,int read_size)
{
	if (ProxyClientConnection)
	{
		int ret;
		if (ProxyClientConnection->ssl)
		{
			ret = SSL_WRITE(ProxyClientConnection->ssl,buf,read_size);
			if (ret <= 0) return(0);
		} else
		{
			ret = send(ProxyClientConnection->datasock,buf,read_size, 0);
			if (ret == SOCKET_ERROR ) return(0);
		}
	}
	return(1);
}
/************************************************************************************************************************/



httpdata* ConnectionHandling::ReadHTTPResponseData(class ConnectionHandling *ProxyClientConnection, httpdata* request, int *ErrorCode)
{

	/* IO VARIABLES TO HANDLE HTTP RESPONSE */
	struct timeval tv;		       /* Timeout for select events */	
	char buf[BUFFSIZE];          /* Temporary buffer where the received data is stored */
	int read_size = 0;			       /* Size of the received data chunk */
	char *lpBuffer = NULL;	       /* Pointer that stores the returned HTTP Data until its flushed to disk or splited into headers and data */
	size_t BufferSize = 0;   /* Size of the returned HTTP Data lpBuffer */
	int BytesToBeReaded = -1;      /* Number of bytes remaining to be readed on the HTTP Stream (-1 means that the number of bytes is still unknown, 0 that we have reached the end of the html data ) */
	httpdata* response = NULL;    /* Returned HTTP Information */

	/* SOME CRITICAL INFORMATION THAT WE WILL GATHER FROM THE HTTP STREAM*/
	unsigned int ChunkEncodeSupported = 0; /* HTTP PROTOCOL FLAG: Server supports chunk encoding */
	unsigned int ConnectionClose	  = 0; /* HTTP PROTOCOL FLAG: Connection close is needed because of server header or protocol I/O error */
	unsigned int ContentLength		  = 0; /* HTTP PROTOCOL FLAG: Server support the ContentLength header */

	/* IO BW LIMIT CONTROL VARIABLES */
	int BwDelay;                   /* Number of miliseconds that the application should wait until reading the next data chunk */
	struct timeval LastTime={0,0}; /* Stores the time when the first data chunk is readed */
	struct timeval CurrentTime;    /* Stores the time when the last data chunk is readed to check for the current bw */
	unsigned int ChunkSize = 0;    /* Stores how many bytes have been readed   */

	/* CHUNK ENCODING VARIABLES  */
	int FirstChunk  =  0;         /* If Chunkencoding is supported, this variable stores the number of processed chunks */
	size_t ChunkDataLength = 0 ;  /* Length of the Buffer that is storing chunks*/
	char *TmpChunkData = NULL;     /* Pointer to a buffer that stores temporary data chunks to verify how many bytes are still needed to be readed */
	unsigned int SkipChunkCLRF = 0; /*Number of bytes (CLRF) to be skipped before the chunk data is readed */
	long chunk=0;				/* Length of the next data chunk */

	/* I/O FILE MAPPING FOR THE HTTP DATA */
	class HTTPIOMapping *HTTPIOMappingData = NULL; /*Filemapping where the returned HTTP data is stored */

	while ( BytesToBeReaded != 0 )
	{
    	tv.tv_sec = HTTP_READ_TIMEOUT;
		tv.tv_usec = 0;
		if ( (BytesToBeReaded!=-1) && (BytesToBeReaded < BUFFSIZE ))
		{
			read_size = ReadBytes(buf,BytesToBeReaded,&tv);
		} else
		{
			read_size = ReadBytes(buf,sizeof(buf),&tv);
		}

		if (read_size <= 0)
		{
			ConnectionClose = 1;  /* There is an error. Close the connection */
			BytesToBeReaded = 0;  /* No more data to be readed */
			if ( (!lpBuffer) && (!HTTPIOMappingData) )
			{
				*ErrorCode = HTTP_RECV_ERROR_CODE_NO_DATA | HTTP_CONNECTION_CLOSE ;
				return (NULL);
			}
		} else 
		{
			/* Asyncronous HTTP REQUEST. Deliver the received data to the browser (if needed)*/
			if (!SendBufferToProxyClient(ProxyClientConnection,buf,read_size))
			{
            	/* Cancel the asyncronous request as the client is not conected anymore*/
				BytesToBeReaded=0;
				ConnectionClose=1;
			}

			/* Write received data to a buffer until filemapping is available */
			if  (!HTTPIOMappingData)
			{
				lpBuffer = (char*) realloc(lpBuffer, BufferSize + read_size + 1);
				memcpy(lpBuffer + BufferSize, buf, read_size);
				BufferSize += read_size;
				lpBuffer[BufferSize] = '\0';
			}

			/* I/O DELAY OPTIONS - CHECK IF WE NEED TO WAIT TO AVOID NETWORK CONGESTION */
			if (BwLimit)
			{
				ChunkSize +=read_size;
				gettimeofday(&CurrentTime,NULL);
				BwDelay = LimitIOBandwidth( ChunkSize, LastTime, CurrentTime,BwLimit);
				if (BwDelay >= 0)
				{
					Sleep(BwDelay);
					gettimeofday(&LastTime,NULL);
					ChunkSize=0;
				}
			}

			/* Check if the remote HTTP Headers arrived completely */
			if (!response)
			{
				response = GetHttpHeadersFromBuffer(lpBuffer);
				/* Extract Information from the remote HTTP Headers */
				if (response)
				{
					BufferSize = BufferSize - response->HeaderSize;
					int HTTPStatusCode = response->GetStatus();
					if (HTTPStatusCode == 0)
					{
						/* Protocolo ERROR - We are reading bad stuff */
						printf("Error: %s\n",request->Header);
						*ErrorCode = HTTP_RECV_ERROR_CODE_INVALID_DATA | HTTP_CONNECTION_CLOSE;
						return (NULL);
					}
					if (HTTPStatusCode == HTTP_STATUS_CONTINUE)
					{
						free(lpBuffer);
						delete response;
						return ReadHTTPResponseData(ProxyClientConnection, request,ErrorCode);
					}
					if (HTTPStatusCode == HTTP_STATUS_NO_CONTENT)
					{
                    	BytesToBeReaded = 0;
					}
					if (response->Header[7] =='0') ConnectionClose = 1;
					
						char *p = response->GetHeaderValue("Connection:", 0);
						if (p)
						{
							if (strnicmp(p, "close", 7) == 0)
							{
								ConnectionClose = 1;
							} else if (strnicmp(p, "Keep-Alive", 10) == 0)
							{
								ConnectionClose = 0;
							}
							free(p);
						} else
						{
							p = response->GetHeaderValue("Proxy-Connection:", 0);
							if (p)
							{
								if (strnicmp(p, "close", 7) == 0)
								{
									ConnectionClose = 1;
								} else if (strnicmp(p, "Keep-Alive", 10) == 0)
								{
									ConnectionClose = 0;
								}
								free(p);
							}
						}

					p = response->GetHeaderValue("Content-Length:", 0);
					if (p)
					{
						if (*p== '-') //Negative Content Length
						{
							ConnectionClose = 1;
							free(lpBuffer);
							lpBuffer = NULL;
							break;
						} else
						{
                        	ContentLength = atoi(p);
							BytesToBeReaded = ContentLength - BufferSize;
						}
						free(p);
					}

					/*HTTP 1.1 HEAD RESPONSES SHOULD NOT SEND BODY DATA.*/
					if (strnicmp(request->Header, "HEAD ", 5) == 0)
					{
						if ((lpBuffer[7] == '1') && (ContentLength))
						{
							free(lpBuffer);
							lpBuffer = NULL;
							ContentLength = 0;
							ConnectionClose = 1; /* We cant trust it */
							break;
						}						
					}

					/*HTTP 1.1 HEAD RESPONSE DOES NOT SEND BODY DATA. */
					if (strnicmp(request->Header, "CONNECT ", 8) == 0)
					{
						BytesToBeReaded=0;
						free(lpBuffer);
						lpBuffer = NULL;
						break;
					}

					p = response->GetHeaderValue( "Transfer-Encoding:", 0);
					if (p)
					{
						if (strnicmp(p, "chunked", 7) == 0)
						{
							ChunkEncodeSupported = 1;
#ifdef _DBG_
							printf("Leido content chunked\n");
#endif
						}
						free(p);
					}
				}
			}

			if (response)
			{
				if (!ChunkEncodeSupported)
				{
					if (!HTTPIOMappingData)
					{
						HTTPIOMappingData = new HTTPIOMapping;
						HTTPIOMappingData->WriteMappingData(BufferSize,lpBuffer + response->HeaderSize);
						free(lpBuffer);
						lpBuffer=NULL;
					} else
					{
						HTTPIOMappingData->WriteMappingData(read_size,buf);
						BufferSize += read_size;
					}

					if ( ContentLength ) 
					{
						BytesToBeReaded = ContentLength - BufferSize;
						if (BytesToBeReaded < 0)
						{
							HTTPServerResponseSize = BytesToBeReaded *(-1);
							HTTPServerResponseBuffer = (char*)malloc(HTTPServerResponseSize+1);
							HTTPIOMappingData->GetMappingData();
							memcpy(HTTPServerResponseBuffer,HTTPIOMappingData->GetMappingData() + HTTPIOMappingData->GetMappingSize() - HTTPServerResponseSize ,HTTPServerResponseSize);
							HTTPServerResponseBuffer[HTTPServerResponseSize]='\0';
							BytesToBeReaded=0;
							break;
						}
					}
				} else {
					/* Decoded chunk */
					if (!HTTPIOMappingData)
					{
						HTTPIOMappingData = new HTTPIOMapping;
						TmpChunkData = (char*)malloc(BufferSize + BUFFSIZE );
						memcpy(TmpChunkData,lpBuffer + response->HeaderSize,BufferSize);
						ChunkDataLength=BufferSize;
						free(lpBuffer);
						lpBuffer=NULL;
					}

					char chunkcode[MAX_CHUNK_LENGTH+1];
					if (FirstChunk>0)
					{
						memcpy(TmpChunkData+ChunkDataLength,buf,read_size);
						ChunkDataLength+=read_size;
					}
					FirstChunk++;
#define CHUNK_DATA_AVAILABLE (ChunkDataLength >= chunk)
#define PARTIAL_CHUNK_DATA_AVAILABLE (ChunkDataLength >= BytesToBeReaded)
#define CHUNK_VALUE strlen(chunkcode) +2
					do
					{
						if (SkipChunkCLRF)
						{
							/* SKIP CLRF anter chunk data */
							if (ChunkDataLength >=SkipChunkCLRF)
							{
								ChunkDataLength -=SkipChunkCLRF;
								memcpy(TmpChunkData,TmpChunkData+SkipChunkCLRF,ChunkDataLength);
								SkipChunkCLRF = 0;
								if ( chunk == 0 )
								{
									BytesToBeReaded = 0;
									break;
								}
							} else {
								BytesToBeReaded = SkipChunkCLRF;
								break;
							}
						}
						if (ChunkDataLength == 0) {
							break;
						}
						if (BytesToBeReaded == -1)
						{
							chunk = ReadChunkNumber(TmpChunkData,ChunkDataLength,(char*)&chunkcode);
							if (chunk==CHUNK_INSUFFICIENT_SIZE)
							{
								BytesToBeReaded = -1;
								break;
							}
							if (chunk==CHUNK_ERROR)
							{
								BytesToBeReaded = 0;
								break;
							}

							/* Skip chunk value */
							ChunkDataLength-= CHUNK_VALUE;
							memcpy(TmpChunkData,TmpChunkData+CHUNK_VALUE,ChunkDataLength);

							if ( CHUNK_DATA_AVAILABLE )
							{
								ChunkDataLength-= chunk;
								HTTPIOMappingData->WriteMappingData(chunk,TmpChunkData);
								memcpy(TmpChunkData,TmpChunkData+chunk,ChunkDataLength);
								BytesToBeReaded = -1;
								SkipChunkCLRF = 2;

							} else
							{
								HTTPIOMappingData->WriteMappingData(ChunkDataLength,TmpChunkData);
								BytesToBeReaded = chunk - ChunkDataLength;
								if (BytesToBeReaded == 0) BytesToBeReaded = -1;
								ChunkDataLength=0;
							}
						} else
						{
							if (PARTIAL_CHUNK_DATA_AVAILABLE)
							{
								HTTPIOMappingData->WriteMappingData(BytesToBeReaded,TmpChunkData);
								ChunkDataLength-=BytesToBeReaded;
								memcpy(TmpChunkData,TmpChunkData + BytesToBeReaded,ChunkDataLength);
								BytesToBeReaded=-1; /* We still dont know how many bytes we need to gather.. */
								SkipChunkCLRF = 2;
							} else
							{
								HTTPIOMappingData->WriteMappingData(ChunkDataLength,TmpChunkData);
								BytesToBeReaded -=ChunkDataLength;
								ChunkDataLength=0;
							}
						}
					} while (ChunkDataLength);
				}
			}

		} /*read size > 0*/
	} /* While end */

	if (!response)
	{
		ConnectionClose = 1;
	} else
	{
		response->UpdateAndReplaceFileMappingData(HTTPIOMappingData);
		if (ChunkEncodeSupported)
		{
			char tmp[100];
			sprintf(tmp,"Content-Length: %i",response->DataSize);
			response->AddHeader(tmp);
			response->RemoveHeader("Transfer-Encoding:");
		}
	}
	if (TmpChunkData) free(TmpChunkData);
	*ErrorCode = HTTP_RECV_ERROR_CODE_NO_ERROR | ConnectionClose;
	return (response);


}
/*******************************************************************************************/

int ConnectionHandling::InitSSLConnection()
{
	if (NeedSSL)
	{
		int err;
#ifdef __WIN32__RELEASE__
		u_long tmp=0;
		ioctlsocket( datasock, FIONBIO, &tmp);
#else
		int tmp = 0;
		ioctl(datasock, FIONBIO, (char *)&tmp);
#endif
		SSL_METHOD *meth = TLSV1_CLIENT_METHOD();

		if (meth == NULL)
		{
			printf("Metho error\n"); exit(1);

		}
		ctx = SSL_CTX_NEW(meth); 		
		if (!ctx)
		{
#ifdef _DBG_
			printf("SSL_CTX_NEW failed\n");
#endif
			closesocket(datasock);
			return 0;
		} 
#ifdef _DBG_
		else
		{
			printf("SSL_CTX_NEW ok\n");
		}
#endif
		ssl=SSL_NEW(ctx);
		SSL_SET_FD(ssl, datasock);
		if ((err = SSL_CONNECT(ssl)) != 1)
		{
#ifdef _DBG_
			int newerr;
			newerr= SSL_GET_ERROR(ssl,err);
			printf("SSL_CONNECT failed: %s\n", strerror(errno));
			printf("SSLError: %i %i\n",newerr,err);
#endif
			SSL_SHUTDOWN(ssl);
			SSL_FREE(ssl);			
			SSL_CTX_FREE(ctx);
			ctx = NULL;
			ssl = NULL;
			closesocket(datasock);
			return(0);
		}
		tmp=0;
#ifdef __WIN32__RELEASE__
		ioctlsocket( datasock, FIONBIO, &tmp);
#else
		ioctl(datasock, FIONBIO, (char *)&tmp);
#endif
	}
	return (1);
}

/*******************************************************************************************/

/*******************************************************************************************/
//! This function reads an HTTP request stream from the remote client connected to the integrated proxy server.
/*!
\param conexion struct returned by a previous accepted conection by the HTTP Proxy engine
\return pointer to a HTTP_DATA Struct with the HTTP request or NULL if the client sent no data.
*/
/*******************************************************************************************/

struct httpdata *ConnectionHandling::ReadHTTPProxyRequestData()
{
	struct timeval tv;
	char buf[BUFFSIZE+1];
	int read_size=0;
	char *lpBuffer=NULL;
	unsigned long BufferSize=0;

	unsigned long	ConnectionClose=0;
	unsigned long	ContentLength=0;

	httpdata* response=NULL;
	int		BytesPorLeer=-1;


	while ( (BytesPorLeer!=0)  && (!ConnectionClose ) )
	{
		tv.tv_sec = HTTP_READ_TIMEOUT;
		tv.tv_usec = 0;
		if (HTTPProxyClientRequestBuffer)
		{
			lpBuffer =HTTPProxyClientRequestBuffer;
			BufferSize=HTTPProxyClientRequestSize;
			HTTPProxyClientRequestBuffer=NULL;
			HTTPProxyClientRequestSize=0;
		} else
		{

			if (!ssl)
			{
				read_size=recv (datasock, buf, BytesPorLeer > sizeof(buf)-1 ? sizeof(buf)-1 :BytesPorLeer  ,0);

			} else
			{
				/* Initializing SSL support */
				if (!NeedSSL)
				{
					NeedSSL = 1;
					if(SSL_ACCEPT(ssl)<=0)
					{
						printf("# SSL ACCEPT ERROR\n");
						/*
						BIO_printf(bio_err,"%s\n","SSL accept error");
						ERR_print_errors(bio_err);
						*/
						return(NULL);
					}
				}
				read_size=SSL_READ(ssl, buf, BytesPorLeer > sizeof(buf)-1 ? sizeof(buf)-1 :BytesPorLeer);	
				pending= SSL_PENDING(ssl);
			}
			if (read_size<=0)
			{
				if (lpBuffer) free(lpBuffer);
				if (response) delete response;

#ifdef _DBG_

				printf("DESCONEXION del Cliente... (leidos 0 bytes - SSL: %i)\n",ssl!=NULL);

#endif
				//FreeConnection(conexion);
				ConnectionClose=1;
				return(NULL);
#ifdef _DBG_
				printf("[%3.3i] ReadHTTPProxyRequestData(): SOCKET CERRADO :?...\n",id);
#endif

			}

			buf[read_size]='\0';
			lpBuffer=(char*)realloc(lpBuffer,BufferSize+read_size+1);
			memcpy(lpBuffer+BufferSize,buf,read_size);
			BufferSize+=read_size;
			lpBuffer[BufferSize]='\0';
		}
		if (!response) //Buscamos el fin de las cabeceras
		{
			response = GetHttpHeadersFromBuffer(lpBuffer);

			if (response)
			{
                BufferSize=BufferSize-response->HeaderSize;
				memcpy(lpBuffer,lpBuffer+response->HeaderSize,BufferSize);
				char *p=response->GetHeaderValue("Content-Length: ",0);
				if (p)
				{
					ContentLength=atoi(p);
					if (p[0]=='-') //Negative Content Length
					{
						ConnectionClose=1;
						free(lpBuffer);
						lpBuffer=NULL;
						break;
					} else
					{
						BytesPorLeer = ContentLength - BufferSize ;
					}
					free(p);
				} else
				{
					BytesPorLeer=0;
				}

				if (BufferSize)
				{
					if (ContentLength)
					{
						if (BufferSize <= ContentLength)
						{
							lpBuffer=(char*)realloc(lpBuffer,BufferSize+1);
							lpBuffer[BufferSize]='\0';

						} else
						{
							lpBuffer=(char*)realloc(lpBuffer,ContentLength+1);
							lpBuffer[ContentLength]='\0';
							HTTPProxyClientRequestBuffer = (char*)malloc(ContentLength-BufferSize+1);
							memcpy( HTTPProxyClientRequestBuffer,lpBuffer + ContentLength, ContentLength-BufferSize);

							//strdup(lpBuffer + ContentLength);
							//HTTPProxyClientRequestSize = BufferSize -ContentLength;
						}
					} else
					{
						HTTPProxyClientRequestBuffer = lpBuffer;
						HTTPProxyClientRequestSize = BufferSize;
						BytesPorLeer = 0;
					}
				}   else {
					free( lpBuffer);
					lpBuffer = NULL;
				}

			}

		} else
		{
			if (BytesPorLeer>0)
			{
				BytesPorLeer-=read_size;
				//BytesPorLeer = ContentLength - BufferSize ;
			}
		}
		if (response)
		{        /*
				 if ( (response->DataSize==0) && (BufferSize) )
				 {
				 //printf("HAY RESPONSE: %s\n",lpBuffer);
				 free(response->Data);
				 }  */
			if (BufferSize)
			{
				if (!ContentLength) 
				{
#ifdef __WIN32__RELEASE__
					MessageBoxA( NULL, response->Data,"Content-Length Error?", MB_OK|MB_ICONINFORMATION );
#else
					printf("Content-Length Error: %s\n",response->Data);
#endif
				}
				response->Data=lpBuffer;
				response->DataSize=BufferSize;
			}

			if (ContentLength)
			{
				if (BytesPorLeer<0)
				{
#ifdef _DBG_
					printf("ReadHTTPProxyRequestData(): ***********\nError leyendo..\n************\n");
#endif
					ConnectionClose=1;
				}			
			}
		}
	}

	if (!response)
	{
		//TODO: revisar si es BufferSize
		response = new httpdata(NULL,0,lpBuffer,BufferSize);
	} else
	{
		if (lpBuffer)
		{
			if (!response->DataSize)
			{
				free(response->Data);
			}
			response->Data = lpBuffer;
			response->DataSize = BufferSize;
		}
	}
/*
	if (ConnectionClose)
	{
		printf("Cerramos la conexion\n");
		FreeConnection();
	} else
	{
		NumberOfRequests++;
		RemovePipeLineRequest();
	}
*/
	return(response);
}
/*******************************************************************************************/

void ConnectionHandling::SetCTX(void *proxyctx)
{
	BIO					*sbio;
	ctx = (SSL_CTX*)proxyctx;
	sbio = BIO_NEW_SOCKET(datasock,BIO_NOCLOSE);
	ssl=SSL_NEW(ctx);
	SSL_SET_BIO(ssl,sbio,sbio);
}

/*******************************************************************************************/

void ConnectionHandling::Acceptdatasock( SOCKET ListenSocket )
{
	int clientLen= sizeof(struct sockaddr_in);
	datasock= (int) accept(ListenSocket,(struct sockaddr *) &webserver,(socklen_t *)&clientLen);
	target=webserver.sin_addr.s_addr;
	strcpy(targetDNS,inet_ntoa(webserver.sin_addr));		
	Connectionid++;
}
/*******************************************************************************************/
void ConnectionHandling::UpdateLastConnectionActivityTime(void)
{
#ifdef __WIN32__RELEASE__
	GetSystemTimeAsFileTime (&LastConnectionActivity);
#else
	time(&LastConnectionActivity);
#endif
}

/*******************************************************************************************/

void ConnectionHandling::CloseSocket(void) 
{ 
	closesocket(datasock); 
}
/*******************************************************************************************/
char *ConnectionHandling::GettargetDNS(void)
{
	return targetDNS;
}
/*******************************************************************************************/
long ConnectionHandling::GetTarget(void) 
{ 
	return target; 
}
/*******************************************************************************************/
int  ConnectionHandling::GetPort(void) 
{ 
	return(port); 
}
/*******************************************************************************************/
int  ConnectionHandling::GetThreadID(void) 
{ 
	return ThreadID; 
}
/*******************************************************************************************/
unsigned int ConnectionHandling::Getio(void) 
{ 
	return InputOutputOperation;
}
/*******************************************************************************************/
void ConnectionHandling::Setio(unsigned int value) 
{ 
	InputOutputOperation = value; 
}
/*******************************************************************************************/
int ConnectionHandling::GetConnectionAgainstProxy(void) 
{ 
	return ConnectionAgainstProxy; 
}
/*******************************************************************************************/
void *ConnectionHandling::IsSSLInitialized(void) 
{ 
	return (void*)ssl; 
}	
/*******************************************************************************************/
void ConnectionHandling::SetBioErr(void *bio)
{
	bio_err = (BIO*)bio;
}

/*******************************************************************************************/

int ConnectionHandling::LimitIOBandwidth(unsigned long ChunkSize, struct timeval LastTime, struct timeval CurrentTime, int MAX_BW_LIMIT)
{

	if ( ( LastTime.tv_usec || LastTime.tv_sec ) && MAX_BW_LIMIT )
	{
		__uint64  TotalTime = ((CurrentTime.tv_usec + CurrentTime.tv_sec*1000000) - (LastTime.tv_usec + LastTime.tv_sec*1000000) ) / 1000;
		if (TotalTime >= MAX_CHECK_TIME_FOR_BW_UTILIZATION ) //check Bw each 200ms
		{
			__uint64  CurrentBW = (ChunkSize *1000 ) / (TotalTime *1024 )  ; //Obtain kbps
			//printf("LimitIOBandwidth::DBG: Hemos tardado %I64d ms for %i bytes - Bandwidth: %I64d kbps (%i KB/s)\n",TotalTime, ChunkSize,CurrentBW,CurrentBW/8);
			if (CurrentBW > MAX_BW_LIMIT  )
			{
				__uint64 WaitFor = (ChunkSize *1000 ) / (MAX_BW_LIMIT *1024) ;
				//printf("LimitIOBandwidth::DBG: Need to wait %i ms\n",WaitFor);
				return((int)WaitFor);
			}
		} else
		{
			return(-1);
		}
	}
	return(0);
}

/*******************************************************************************************************/
FILETIME ConnectionHandling::GetLastConnectionActivityTime(void)
{
	return ( LastConnectionActivity);

}
/*******************************************************************************************************/