//#define _DBG_
#include "ConnectionHandling.h"
#include "misc.h"
#include <stdio.h>
#include <stdlib.h>



int InitializeSSLLibrary()
{

	return(1);
}





/*******************************************************************************************************/
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
int ConnectionHandling::StablishConnection(void)
{
	fd_set fds, fderr;
	struct timeval tv;

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

	NumberOfRequests = 0;
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
		return (0);
	}

#ifdef _DBG_
	printf("StablishConnection: Socket CONNECTED Conexion %i (%s:%i)\n",id,inet_ntoa(webserver.sin_addr),port);

#endif
	UpdateLastConnectionActivityTime();
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

	return (1);
}


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
	tlastused.dwHighDateTime = 0;
	tlastused.dwLowDateTime = 0;
#else
	tlastused = 0;
#endif
	NumberOfRequests = 0;
	io = 0;
	PIPELINE_Request = NULL;
	PIPELINE_Request_ID = 0;
	PENDING_PIPELINE_REQUESTS = 0;
	CurrentRequestID = 0;
	id = 0;
	BwLimit = 0;
	DownloadLimit= 0;
	ThreadID = 0;
	ConnectionAgainstProxy = 0;

	HTTPServerResponseBuffer=NULL;
	HTTPServerResponseSize=0;

	HTTPProxyClientRequestBuffer=NULL;
	HTTPProxyClientRequestSize = 0;

}


ConnectionHandling::~ConnectionHandling()
{

	if (target)
	{
		if (datasock)
		{
			shutdown(datasock,2);
			target=0;
			closesocket(datasock);
		}

		for (int i=0;i<PENDING_PIPELINE_REQUESTS;i++)
		{
			delete PIPELINE_Request[i];

		}
		if (PIPELINE_Request)
		{
			free(PIPELINE_Request);
			PIPELINE_Request = NULL;
		}
		target = 0;
	}
}

int ConnectionHandling::GetConnection(class HTTPAPIHANDLE *HTTPHandle) 
{
	if (datasock==0)
	{
		io = 1;
		target=HTTPHandle->GetTarget();
		port=HTTPHandle->GetPort();
		NeedSSL = HTTPHandle->IsSSLNeeded();

		if (HTTPHandle->ProxyEnabled())
		{
			port=atoi(HTTPHandle->GetHTTPConfig(ConfigProxyPort));
			ConnectionAgainstProxy=1;
		} else
		{
			ConnectionAgainstProxy=0;
		}	

		int ret = StablishConnection();
		if (!ret)
		{
			io = 0;
			//			*id = 0;
			return(0);
		}

		BwLimit=HTTPHandle->GetDownloadBwLimit();
		DownloadLimit=HTTPHandle->GetDownloadLimit();
		ThreadID = HTTPHandle->GetThreadID();

		HTTPHandle->SetConnection((void*)this);
		io=0;

	} else
	{
//		printf("LLamada obviada a GetConnection\n");
	}
	return(1);
}


void ConnectionHandling::Disconnect(void)
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
	io=0;
#ifdef __WIN32__RELEASE__
	tlastused.dwHighDateTime=0;
	tlastused.dwLowDateTime=0;
#else
	tlastused=0;
#endif

}

void ConnectionHandling::FreeConnection(void)
{

//	printf("llamando a free connection..\n");
	RemovePipeLineRequest();

	Disconnect();

	if (PENDING_PIPELINE_REQUESTS)
	{
#ifdef _DBG_
		printf("LLAMANDO A STABLISH CONNECTION desde FreeConnection\n"); 
#endif
		io=1;
		int i = StablishConnection();
		if (i)
		{
			for (i = 0; i < PENDING_PIPELINE_REQUESTS; i++)
			{
//				printf("reenviando peticion HTTP %i\n",i);
				SendHTTPRequest(PIPELINE_Request[i]);
			}
		} else
		{
			/* TODO 1 : Que pasa si no podemos reconectar?... COMO SE GESTIONAN los errores... */
			datasock = 0;
#ifdef _DBG_
			printf("ERROR UNABLE TO RECONNECT\n");
#endif

		}
	} else
	{
		target=TARGET_FREE;
		port=TARGET_FREE;
		NeedSSL=TARGET_FREE;
	}
	io=0;
}

int ConnectionHandling::RemovePipeLineRequest(void)
{
	if (PENDING_PIPELINE_REQUESTS) 
	{
		for (int i=0;i<PENDING_PIPELINE_REQUESTS -1;i++)
		{
			PIPELINE_Request[i]=PIPELINE_Request[i +1];
			PIPELINE_Request_ID[i]=PIPELINE_Request_ID[i+1];		
		}
		PENDING_PIPELINE_REQUESTS--;
		PIPELINE_Request=(httpdata**)realloc(PIPELINE_Request,sizeof(httpdata*) * (PENDING_PIPELINE_REQUESTS));
		PIPELINE_Request_ID= (unsigned long *) realloc(PIPELINE_Request_ID,sizeof(unsigned long) * PENDING_PIPELINE_REQUESTS);		
		if (!PENDING_PIPELINE_REQUESTS)
		{
			PIPELINE_Request=NULL;
			PIPELINE_Request_ID = NULL;
			return(0);
		} 
	}
	return(PENDING_PIPELINE_REQUESTS);

}

unsigned long ConnectionHandling::AddPipeLineRequest(httpdata *request)//, unsigned long RequestID)
{
#ifdef _DBG_
	printf("*** AddPipeLineRequest: Añadiendo %i en conexion %i (%i +1)\n",CurrentRequestID,id,PENDING_PIPELINE_REQUESTS);
#endif
	PIPELINE_Request=(httpdata* *)realloc(PIPELINE_Request,sizeof(httpdata*) * (PENDING_PIPELINE_REQUESTS+1));
	PIPELINE_Request[PENDING_PIPELINE_REQUESTS]=request;

	PIPELINE_Request_ID= (unsigned long *) realloc(PIPELINE_Request_ID,sizeof(unsigned long) * (PENDING_PIPELINE_REQUESTS+1));	
	PIPELINE_Request_ID[PENDING_PIPELINE_REQUESTS ]=CurrentRequestID++; //RequestID++;
	PENDING_PIPELINE_REQUESTS++;	
	//UnLockMutex(&lock);
	/* TODO 1 : Revisar de donde sale ese unlockmutex- Es necesario? el acceso esta restringido con el mutex global LOCK */
	return(PIPELINE_Request_ID[PENDING_PIPELINE_REQUESTS -1]);
}





int ConnectionHandling::SendHTTPRequest(httpdata* request)
{


#ifdef _DBG_
	printf("\nSendHTTPRequest status:\n");
	printf("ConnectionAgainstProxy: %i\n",ConnectionAgainstProxy);
	printf("NeedSSL: %i\n",NeedSSL);
	printf("port: %i\n",port);
	printf("conexion->NumberOfRequests: %i\n",NumberOfRequests);
	printf("ENVIANDO: %s\n",request->Header);
#endif
	if (!request)  return(0);


	if ( (NeedSSL) && (!ssl) && 
		( ((NumberOfRequests==0) && (!ConnectionAgainstProxy ) ) || //First SSL Request
		(  (NumberOfRequests==1) && ( ConnectionAgainstProxy ) ) ) )   //Seccond HTTP Request against the HTTP Proxy Host
	{
		if (! InitSSLConnection()) return(0);
	}

	if (ssl) 
	{
		int err=SSL_WRITE(ssl, request->Header, request->HeaderSize);
		if (err>0)
		{
			if (request->DataSize)
			{
				err=SSL_WRITE(ssl, request->Data, request->DataSize);
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

		int err = send(datasock, request->Header, request->HeaderSize, 0);
		if (err > 0)
		{
			if (request->DataSize)
			{
				err = send(datasock, request->Data, request->DataSize, 0);
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


#ifdef __WIN32__RELEASE__
	GetSystemTimeAsFileTime (&tlastused);
#else
	time(&tlastused);
#endif
	return (1);
}

/**********************************************************/
httpdata* ConnectionHandling::SendAndReadHTTPData(class HTTPAPIHANDLE *HTTPHandle,httpdata *request)
{
	int ret = GetConnection(HTTPHandle);
	if (ret)
	{
		AddPipeLineRequest(request);
		SendHTTPRequest(request);
		Threading mymutex;
		return (ReadHTTPResponseData(NULL,request,&mymutex) );
	} else
	{
		return(NULL);
	}
}
/**********************************************************/


httpdata* ConnectionHandling::ReadHTTPResponseData(class ConnectionHandling *ProxyClientConnection, httpdata* request,class Threading *ExternalMutex)// void *lock)
{

	/* IO VARIABLES TO HANDLE HTTP RESPONSE */
	struct timeval tv;		       /* Timeout for select events */
	fd_set fdread, fds, fderr;     /* descriptors to be signaled by select events */
	char buf[BUFFSIZE+1];          /* Temporary buffer where the received data is stored */
	int read_size;			       /* Size of the received data chunk */
	char *lpBuffer = NULL;	       /* Pointer that stores the returned HTTP Data until its flushed to disk or splited into headers and data */
	unsigned int BufferSize = 0;   /* Size of the returned HTTP Data lpBuffer */
	char *HeadersEnd = NULL;       /* Pointer to the received buffer that indicates where the HTTP headers  end and HTTP data begins */
	int offset = 0;                /* Number of bytes from the end of headers to the start of HTTP data. Usually 4bytes for "\r\n\r\n" if its RFC compliant*/
	int BytesToBeReaded = -1;      /* Number of bytes remaining to be readed on the HTTP Stream (-1 means that the number of bytes is still unknown, 0 that we have reached the end of the html data ) */
	int i;                         /* Just a counter */
	int pending      =  0;         /* Signals if there is Buffered data to read under and SSL connection*/
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
	int ChunkNumber  =  0;         /* If Chunkencoding is supported, this variable stores the number of fully received chunks */
	char *encodedData = NULL;      /* Pointer to a buffer that stores temporary data chunks to verify how many bytes are still needed to be readed */
	unsigned int encodedlen = 0 ;  /* Length of the encodedData Buffer */
	char *TmpChunkData = NULL;     /* Pointer to a buffer that stores temporary data chunks to verify how many bytes are still needed to be readed */

	/* I/O FILE MAPPING FOR THE HTTP DATA */
	class HTTPIOMapping *HTTPIOMappingData = NULL;

	//LockMutex(&conexion->lock);
	lock.LockMutex();
	tv.tv_sec = HTTP_READ_TIMEOUT;
	tv.tv_usec = 0;

	while (BytesToBeReaded != 0)
	{
		if (HTTPServerResponseBuffer)
		{
			/* Reuse previously readed data */
			lpBuffer = HTTPServerResponseBuffer;
			BufferSize = read_size =HTTPServerResponseSize;
			HTTPServerResponseBuffer = NULL;
			HTTPServerResponseSize = 0;
			UpdateLastConnectionActivityTime();
		   //	printf("Quedan datos: !%s!\n",lpBuffer);

		} else
		{

			/* Wait for readable data at the socket */
			FD_ZERO(&fds);
			FD_SET(datasock, &fds);
			FD_ZERO(&fderr);
			FD_SET(datasock, &fderr);
			FD_ZERO(&fdread);
			FD_SET(datasock, &fdread);

			if (!pending)
			{
				i = select((int) datasock + 1, &fdread, NULL,&fderr, &tv);

				UpdateLastConnectionActivityTime();
				/* No events from the select means that connection timed out (due to network error, read timeout or maybe and http protocol error */
				if ((i == 0))
				{
					//Como liberamos lpBuffer con el mapping, debemos verificar que exista "hTmpFilename" o lo que es lo mismo, la struct "response"
					if ( (!lpBuffer) && (!HTTPIOMappingData) )
					{
						lock.UnLockMutex();
						//UnLockMutex(&conexion->lock);
						ExternalMutex->LockMutex();
						//LockMutex(lock);
						FreeConnection();
						//FreeConnection(conexion);
						ExternalMutex->UnLockMutex();
						if (ConnectionAgainstProxy)
						{
							return ( NULL) ;
						} else
						{
							//return (InitHTTPData(NULL,0,NULL,0));
							return (new httpdata) ;
						}
					}
					ConnectionClose = 1;
					break;
				}
				read_size = 1;
			}

			/* Verify that there is pending readable data (over ssl) */
			if ((FD_ISSET(datasock, &fdread)) || pending)
			{

				if (ssl)
				{
					read_size=SSL_READ(ssl, buf, BytesToBeReaded> sizeof(buf)-1 ? sizeof(buf)-1 :BytesToBeReaded);
					pending= SSL_PENDING(ssl);
					//int ret=SSL_get_error(ssl,read_size);
					SSL_GET_ERROR(ssl,read_size);
#ifdef _DBG_
					printf("SSL: read: %i bytes (pending %i)\n",read_size,pending);
#endif
				} else
				{
					read_size = recv(datasock, buf, BytesToBeReaded > sizeof(buf) - 1 ? sizeof(buf) - 1 : BytesToBeReaded, 0);
				}
				if (read_size>0) buf[read_size]='\0'; else *buf='\0';
#ifdef _DBG_
				if (read_size>0)
				{
					printf("---------- read: \n%s\n-----------\n",buf); fflush(stdout);
				}
#endif
			}

			/* Verify if there are errors */
			if ((!pending) && ((FD_ISSET(datasock, &fderr)) || (read_size <= 0)))
			{
//				printf("llegamos aqui con read_size = %i\n",read_size);
				if (read_size <= 0)
				{
					if ( (!lpBuffer) && (HTTPIOMappingData == NULL) )
					{
						/* If the socket is reused for more than one request, always try to send it again. (assume persistent connections)*/
						lock.UnLockMutex();
						//UnLockMutex(&conexion->lock);
						if (NumberOfRequests > 0)
						{
#ifdef _DBG_
							printf("CONECTA::DBG Error recv() en peticion reutilizada\n");
							printf("LLAMANDO A StablishConnection desde peticion fallida reutilizada\n");
#endif
							//LockMutex(lock);
							ExternalMutex->LockMutex();
							shutdown(datasock,2);
							closesocket(datasock);
							i = StablishConnection();
							if (!i)
							{
								FreeConnection();
								ExternalMutex->UnLockMutex();
								//UnLockMutex(lock);
								return (NULL);
							}
							for (i = 0; i <= PENDING_PIPELINE_REQUESTS - 1; i++)
							{
								SendHTTPRequest(PIPELINE_Request[i]);
							}

							//UnLockMutex(lock);
							ExternalMutex->UnLockMutex();
							return ReadHTTPResponseData(ProxyClientConnection, request, ExternalMutex);
						} else
						{
							//						printf("peticiones <=0\n");
#ifdef _DBG_
							printf("CONECTA::DBG Error recv(). Se han recibido 0 bytes. Purgando conexion..\n");
#endif
							//LockMutex(lock);
							ExternalMutex->LockMutex();
							FreeConnection();
							ExternalMutex->UnLockMutex();
							//UnLockMutex(lock);
							//return (InitHTTPData(NULL,0,NULL,0));
							return ( new httpdata);
						}
					}

				}
#ifdef _DBG_
				if (FD_ISSET(datasock, &fderr)) printf("es fderr\n");
#endif
				ConnectionClose = 1;
				BytesToBeReaded = 0;
			}
			/* END OF I/O READ FUNCTIONS. NOW WE ARE GOING TO PARSE THE DATA */


			/* WRITE RECEIVED DATA (IF POSSIBLE) TO A TEMPORARY FILE  */
			if (read_size>0) 
			{
				/* Asyncronous HTTP REQUEST. Deliver the received data to the browser */
				if (ProxyClientConnection!=NULL)
				{
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
                	UpdateLastConnectionActivityTime();
					if (ProxyClientConnection->ssl)
					{
						if (SSL_WRITE(ProxyClientConnection->ssl,buf,read_size) <=0)
						{
							/* Cancel the asyncronous request due to an SSL communication Error with the proxy client. */
							/* We should debug this and raise an alert */
							BytesToBeReaded=0;
							ConnectionClose=1;
						}
					} else
					{
						if (send(ProxyClientConnection->datasock,buf,read_size, 0) == SOCKET_ERROR ) 
						{
							/* Cancel the asyncronous request as the Proxy client have been disconnected somehow*/
							BytesToBeReaded=0;
							ConnectionClose=1;
						}
					}

				}
				if  (HTTPIOMappingData)
				{
					//printf("Añadiendo: %i bytes\n",read_size);
					HTTPIOMappingData->WriteMappingData(read_size,buf);
					BufferSize += read_size;
				} else
				{
					lpBuffer = (char*) realloc(lpBuffer, BufferSize + read_size + 1);
					memcpy(lpBuffer + BufferSize, buf, read_size);
					BufferSize += read_size;
					lpBuffer[BufferSize] = '\0';
				}
			}
		}


		/* I/O DELAY OPTIONS - CHECK IF WE NEED TO WAIT TO AVOID NETWORK CONGESTION */
		if ( (BwLimit) && (read_size>0) )
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
		if ( (!HeadersEnd) && (read_size >0) )//Buscamos el fin de las cabeceras
		{
			char *p = strstr(lpBuffer, "\r\n\r\n");
			if (p)
			{
				offset = 4;
				HeadersEnd = p;
			}
			p = strstr(lpBuffer, "\n\n"); // no rfc compliant (like d-link routers)
			if (p)
				if ((!HeadersEnd) || (p < HeadersEnd))
				{
					offset = 2;
					HeadersEnd = p;
				}

				/* Extract Information from the remote HTTP Headers */
				if (HeadersEnd)
				{

					if (strnicmp(lpBuffer, "HTTP/1.1 100 Continue", 21) == 0)
					{ //HTTP 1.1 Continue Message.
						free(lpBuffer);
						return ReadHTTPResponseData(ProxyClientConnection, request, ExternalMutex);

					}
					response = new httpdata (lpBuffer,(unsigned int)(HeadersEnd - lpBuffer) + offset);

#ifdef _DBG_
					printf("Value: %s\n",response->Header);
#endif
					if (response->HeaderSize>8)
					{
						if (strcmp(response->Header+9,"204")==0)
						{
							return(response);
						}
						//Use "Connection: Close" as default for HTTP/1.0
						if (response->Header[7] =='0') ConnectionClose = 1;

					}
					p = response->GetHeaderValue("Connection:", 0);
					//p = GetHeaderValue(response->Header, "Connection:", 0);
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
						//p = response->GetHeaderValue("Proxy-Connection:", 0);
						//p = GetHeaderValue(response->Header, "Proxy-Connection:", 0);
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
					if ((p = response->GetHeaderValue("Content-Length:", 0))!= NULL)
					{
						ContentLength = atoi(p);
						if (p[0] == '-') //Negative Content Length
						{
							ConnectionClose = 1;
							free(lpBuffer);
							lpBuffer = NULL;
							break;
						} else
						{
							BytesToBeReaded = ContentLength - BufferSize
								+ response->HeaderSize;// - offset;
						}
						free(p);
					}
					if (strnicmp(request->Header, "HEAD ", 5) == 0)
					{ //HTTP 1.1 HEAD RESPONSES SHOULD NOT SEND BODY DATA.
						if ((lpBuffer[7] == '1') && (ContentLength))
						{
							free(lpBuffer);
							lpBuffer = NULL;
							break;
						}
					}
					if (strnicmp(request->Header, "CONNECT ", 8) == 0)
					{ //HTTP 1.1 HEAD RESPONSE DOES NOT SEND BODY DATA.
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
					BufferSize = BufferSize - response->HeaderSize;
					//Check Status code. //HTTP/1.1 204

					HTTPIOMappingData = new HTTPIOMapping(BufferSize,lpBuffer + response->HeaderSize);
					if (BufferSize) {
						TmpChunkData = (char*)malloc(BufferSize + BUFFSIZE +1);
						memcpy(TmpChunkData,lpBuffer + response->HeaderSize,BufferSize);
						encodedlen=BufferSize;
						TmpChunkData[BufferSize]='\0';
					}
					free(lpBuffer);
					lpBuffer=NULL;
				}

		}


		/* We Must Validate here the chunked Data */
		if ( (ChunkEncodeSupported) && (read_size>0 ) )
		{
			char chunkcode[MAX_CHUNK_LENGTH+1];
			char *p;
			unsigned long chunk=1;

			encodedData = TmpChunkData;
			if (ChunkNumber>0)
			{
				/* Si no es asi, los datos ya los hemos copiado de lpBuffer + response->HeaderSize */
				memcpy(TmpChunkData+encodedlen,buf,read_size);
				encodedlen+=read_size;
				TmpChunkData[encodedlen]='\0';
			}
			do
			{
#ifdef _DBG_
				printf("\n\n*+++++++++++++++++++++++*\n");
				printf("Parseando buffer de %i bytes\n",encodedlen);
				if (encodedlen==2) printf("%x %x\n",encodedData[0],encodedData[1]);

#endif

				if (BytesToBeReaded <=0) 
				{
#ifdef _DBG_
					printf("%s\n",encodedData);
					printf("\n\n*----------------*\n");
#endif
					if (encodedlen<=2) break;
					//printf("Bytes por leer: %i\n",BytesToBeReaded);
					if (ChunkNumber !=0) //Sobrepasamos el CLRF del principio
					{
						encodedData+=2;
						encodedlen-=2;
					}
					/* Read the next chunk Value (example 1337\r\n*/
					if (encodedlen>=MAX_CHUNK_LENGTH)
					{
						//memset(chunkcode,0,sizeof(chunkcode));
						memcpy(chunkcode,encodedData,MAX_CHUNK_LENGTH);
						chunkcode[MAX_CHUNK_LENGTH]='\0';
						p=strstr(chunkcode,"\r\n");
						if (!p)
						{
#ifdef _DBG_
							//printf("Chunk encoding Error. Data chunk Format error %s\n",encodedData);
							printf("Chunk encoding Error. Data chunk Format error %s\n",chunkcode);
							printf("MORE: %s\n",encodedData);
							//exit(1);
#endif
							ChunkEncodeSupported = 0; //avoid further tests
							ConnectionClose=1; //ERRRORR!!!!
							free(TmpChunkData);
							TmpChunkData=NULL;
							break;
						}
					} else
					{
						memcpy(chunkcode,encodedData,encodedlen);
						chunkcode[encodedlen]='\0';
						p=strstr(chunkcode,"\r\n");
						if (!p)
						{
#ifdef _DBG_
							printf("Chunk encoding Error. Not enought data. Waiting for next chunk\n");
#endif
							if (ChunkNumber !=0) encodedlen+=2; //restauramos la longitud del chunk que vamos a analizar
							break;
						}
					}
					ChunkNumber++;
					*p='\0';
					chunk=strtol(chunkcode,NULL,16);
#ifdef _DBG_
					printf("Leido chunk de valor : %i\n",chunk);
#endif
					if (chunk==0)
					{
						BytesToBeReaded=0;
						break;
					}

					if ( (unsigned int) encodedlen >= 2 + strlen(chunkcode)+chunk)
					{
#ifdef _DBG_
						printf("Encodedlen (%i) >= 2 + strlen(chunkcode)+chunk\n",encodedlen);
#endif
						encodedlen-=2+chunk+strlen(chunkcode);
						//						printf("ahora quedan %i bytes\n");
						//printf("Exactamente: %s\n",encodedData);
						//encodedData+=2+chunk+strlen(chunkcode);
						BytesToBeReaded = -1;
						//memcpy(TmpChunkData,encodedData,encodedlen);
						//HACK: REVISAR SI FUNCIONA.
						memcpy(TmpChunkData,encodedData+2+chunk+strlen(chunkcode),encodedlen);

						encodedData=TmpChunkData;
						TmpChunkData[encodedlen]='\0';

					} else
					{
						encodedlen-=2 + (unsigned int)strlen(chunkcode);
						BytesToBeReaded = chunk - encodedlen;
						if (BytesToBeReaded == 0) BytesToBeReaded = -1;
						encodedlen=0;

#ifdef _DBG_
						printf("No llegan los datos: BytesToBeReaded asignado a %i\n",BytesToBeReaded);
#endif
					}
				} else
				{
#ifdef _DBG_
					printf("Tenemos un trozo de %i bytes . necesitamos %i bytes\n",encodedlen,BytesToBeReaded);
#endif
					if ((int)encodedlen >= BytesToBeReaded)
					{

						encodedData+=BytesToBeReaded;
						encodedlen-=BytesToBeReaded;
						BytesToBeReaded=-1;
						memcpy(TmpChunkData,encodedData,encodedlen);
						TmpChunkData[encodedlen]='\0';
#ifdef _DBG_
						printf("Nos quedan %i bytes para seguir trabajando\n",encodedlen);
#endif
					} else
					{
						BytesToBeReaded -=encodedlen;
						encodedlen=0;
#ifdef _DBG_
						printf("Seguimos necesitando %i bytes\n",BytesToBeReaded);
#endif
					}
				}
			} while (encodedlen);
#ifdef _DBG_
			printf("Salimos del bucle\n");
#endif
		}

		if ( (ContentLength) && (read_size>0) )
		{
			BytesToBeReaded = ContentLength - BufferSize;
			if (BytesToBeReaded < 0)
			{
#ifdef _DBG_
				printf("***********\nError leyendo..\n************\n");
#endif
				HTTPServerResponseSize = BytesToBeReaded *(-1);
				HTTPServerResponseBuffer = (char*)malloc(HTTPServerResponseSize+1);
				HTTPIOMappingData->GetMappingData();
				memcpy(HTTPServerResponseBuffer,HTTPIOMappingData->GetMappingData() + HTTPIOMappingData->GetMappingSize() - HTTPServerResponseSize ,HTTPServerResponseSize);
				HTTPServerResponseBuffer[HTTPServerResponseSize]='\0';
				BytesToBeReaded=0;
			}
		}

		/* TRIGGER THE DOWNLOAD LIMIT TO AVOID DEAD LOCKS When Scanning*/
		if (DownloadLimit!=0 )
		{
			if (response)
			{
				if ( (response->DataSize + response->HeaderSize) >= DownloadLimit )
				{
					BytesToBeReaded=0;
					ConnectionClose=1;

				}
			} else 
			{
				if (BufferSize >= DownloadLimit)
				{
					BytesToBeReaded=0;
					ConnectionClose=1;
				}
			}
		}



	}
#ifdef _DBG_
	printf("End of reading\n");
	if (response)
	{
		printf("Headers: %s\n",response->Header);
	}
#endif


	/*** END OF READ LOOP **/
	if (!response)
	{
		/* Headers were not found. We can assume that no HTTP protocol data have been returned. */
		response= new httpdata; //InitHTTPData(NULL,0,NULL,0);
		if (lpBuffer)
		{
			free(response->Data);
			response->Data=lpBuffer;
			response->DataSize = BufferSize;
		}
	} else
	{
		if (HTTPIOMappingData)
		{
			if (BufferSize)
			{
				//printf("Reemplazamos filemaping\n");
				response->UpdateAndReplaceFileMappingData(HTTPIOMappingData);
				//printf("prueba3: %8.8X - %s\n",response->Data,response->Data);
//				printf("Datos: %s\n",response->Data);
                //printf("goo\n");
				fflush(stdout);
			} else {
				delete HTTPIOMappingData;
            }

		}
	}
	if (TmpChunkData) free(TmpChunkData);

	ExternalMutex->LockMutex();
	if (ConnectionClose)
	{
		if (HTTPServerResponseBuffer)
		{
			free(HTTPServerResponseBuffer);
			HTTPServerResponseBuffer=NULL;
			HTTPServerResponseSize=0;
		}
		FreeConnection();
	} else
	{
		NumberOfRequests++;
		RemovePipeLineRequest();
		io = 0;
	}
	ExternalMutex->UnLockMutex();
	lock.UnLockMutex();

	/*
	printf("HEMOS TARDADO: %i\n",((CurrentTime.tv_usec + CurrentTime.tv_sec*1000000) - (StartTime.tv_usec + StartTime.tv_sec*1000000) ) / 1000);
	printf("Total: %i bytes\n",TotalSize);
	*/
#ifdef _DBG_
	printf("salimos de aqui..\n");
	printf("response->header: (%i bytes) %s\n",response->HeaderSize,response->Header);
	printf("response->Data: (%i bytes) %s\n",response->DataSize,response->Data);

#endif
/*HACK:
  Somewhere there is an small small bug when reading chunk-encoding data. Scenario:
  - Transfer-Encoding: chunk-encoded
  - Connection Keeped alive (its at least the second response)
  - One or Two extra bytes "\n" or "\r\n" are not readed before the final of a previous response chunk 0\r\n

  Maybe the end chunk is signaled and the \r\n string have not been readed (because of full buffer or because the server didnt send all the data yet.
  At this point the client wont try to re\read again so that data will be readed
  at the second request and therefore some information extracted by HTTP headers
  will be corrupted, like data->statuscode, as there is no status code at the first
  line.

  This small fix will remove extra CLRF at the start of the requests
*/
 if ( (response->HeaderSize>2) && ( (*response->Header=='\r') || (*response->Header=='\n') ) )
 {
	int n=0;
	while ( (response->Header[n]=='\r') || (response->Header[n]=='\n') )
	{
		n++;
	}
	memcpy(response->Header,response->Header+n,response->HeaderSize-n);
	response->HeaderSize-=n;
	response->Header[response->HeaderSize]=0;
	//printf("Fixed CLRF %i bytes\n",n);
 }


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

//	unsigned long	ChunkEncodeSupported=0;
	unsigned long	ConnectionClose=0;
	unsigned long	ContentLength=0;
	char *HeadersEnd=NULL;

	int offset=0;
	httpdata* response=NULL;
	int		BytesPorLeer=-1;
	unsigned int pending = 0;

	tv.tv_sec = HTTP_READ_TIMEOUT;
	tv.tv_usec = 0;

	while ( (BytesPorLeer!=0)  && (!ConnectionClose ) )
	{
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
				if (response) delete response;//FreeHTTPData(response);

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
		if (!HeadersEnd) //Buscamos el fin de las cabeceras
		{
			char *p=strstr(lpBuffer,"\r\n\r\n");
			if (p)
			{
				offset=4; 
				HeadersEnd=p; 
			} 
			p=strstr(lpBuffer,"\n\n"); // no rfc compliant (like d-link routers)
			if ( (p)  && ( (!HeadersEnd) || (p<HeadersEnd)) )
			{
				offset=2; 					
				HeadersEnd=p; 
			}
			if (HeadersEnd)
			{
				//printf("HEADERS END..\n");
				response = new httpdata (lpBuffer,(unsigned int)(HeadersEnd-lpBuffer) + offset);
#ifdef _DBG_
				//printf("[%3.3i] ReadHTTPProxyRequestData(): HeaderSize vale %i de %ibytes\n",conexion->id,response->HeaderSize,BufferSize);
#endif

				if ((p=response->GetHeaderValue("Content-Length: ",0))!=NULL) 
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
						// BytesPorLeer = ContentLength - BufferSize + response->HeaderSize;// - offset;
						BytesPorLeer = ContentLength - (BufferSize - response->HeaderSize ) ;
					}
					free(p);
				} else
				{
					BytesPorLeer=0;
				}				
				BufferSize=BufferSize-response->HeaderSize;
				memcpy(lpBuffer,lpBuffer+response->HeaderSize,BufferSize);				
				lpBuffer=(char*)realloc(lpBuffer,BufferSize+1);
				lpBuffer[BufferSize]='\0';
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
		{
			if ( (response->DataSize==0) && (BufferSize) )
			{
				//printf("HAY RESPONSE: %s\n",lpBuffer);
				free(response->Data);				
			}
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
	if (ConnectionClose)
	{
		FreeConnection();
	} else
	{
		NumberOfRequests++;
		RemovePipeLineRequest();
		io=0;
	}
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
