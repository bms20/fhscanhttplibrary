#ifndef __CONNECTIONHANDLING_H__
#define __CONNECTIONHANDLING_H__

#include "Build.h"
#include "Threading.h"
#include "HTTPHANDLE.h"
#include "HTTP.h"
#include "FileMapping.h"
#include "SSLModule.h"

#ifdef __WIN32__RELEASE__
#include <sys/timeb.h>
#include <process.h>
#include <time.h>
#include <windows.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <ctype.h>
#include <time.h>
#include <sys/timeb.h>
#define FILETIME time_t
#endif

#ifdef _OPENSSL_SUPPORT_
/*
 #include <openssl/crypto.h>
 #include <openssl/x509.h>
 #include <openssl/pem.h>
 #include <openssl/ssl.h>
 #include <openssl/err.h>
 #define SSL_CTX_SET_TMP_DH(ctx,dh) \
		 SSL_CTX_CTRL(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)dh)
*/
 	#define KEYFILE		"server.pem"
	#define CA_LIST		"root.pem"
	#define PASSWORD	"password"
	#define DHFILE		"dh1024.pem"

#endif /* USE_SSL */



#define HTTP_READ_TIMEOUT		10
#define HTTP_CONN_TIMEOUT		10
#define BUFFSIZE								4096 //default read buffer
#define MAX_CHECK_TIME_FOR_BW_UTILIZATION  200
#define HTTP_CONN_TIMEOUT 10
#define HTTP_READ_TIMEOUT 10
#define HTTP_MAX_CONNECTIONS 100

#define MAX_CHUNK_LENGTH						10
#define ERROR_MORE_DATA_NEEDED 					-1
#define ERROR_PARSING_DATA     					0xFFFFFF

#define TARGET_FREE   							0

class ConnectionHandling : public SSLModule 
{
	long 			 target;
	char 			 targetDNS[256];
	int 			 port;
	#ifdef _OPENSSL_SUPPORT_
	int 			 NeedSSL; //IsSSLNeeded
	SSL_CTX *		 ctx;
	SSL *			 ssl;
	BIO				*bio_err;
	#endif
	unsigned int	 datasock;
	struct sockaddr_in webserver;
	//FILETIME 		 tlastused;
	class Threading  lock;	//avoid pipelining
	unsigned int	 NumberOfRequests;
	unsigned int	 io;
	int				 PENDING_PIPELINE_REQUESTS;

	struct httpdata	**PIPELINE_Request;//httpdata**		 PIPELINE_Request;
	unsigned long*	 PIPELINE_Request_ID; //Identificador de la conexion
	unsigned long	 CurrentRequestID;
	int 			 id;
	unsigned int	 BwLimit;
	unsigned int	 DownloadLimit;
#ifdef __WIN32__RELEASE__
	int				 ThreadID;
#else
	pthread_t		 ThreadID;
#endif
	int				ConnectionAgainstProxy;
/*
	char			*BufferedData;
	unsigned int	BufferedDataSize;
  */

	char *HTTPServerResponseBuffer;
	unsigned int HTTPServerResponseSize;

	char *HTTPProxyClientRequestBuffer;
	unsigned int HTTPProxyClientRequestSize;


	int LimitIOBandwidth(unsigned long ChunkSize, struct timeval LastTime, struct timeval CurrentTime, int MAX_BW_LIMIT);
	int StablishConnection(void);

	#ifdef _OPENSSL_SUPPORT_
		int InitSSLConnection();
	#endif
public:
	FILETIME 		 tlastused;
	ConnectionHandling();
	~ConnectionHandling();
	void			FreeConnection(void);
	int				RemovePipeLineRequest(void);
	unsigned long	AddPipeLineRequest(httpdata *request);//, unsigned long RequestID);
	int				GetConnection(class HTTPAPIHANDLE *HTTPHandle);	
	int				SendHTTPRequest(httpdata* request);
	
	httpdata		*SendAndReadHTTPData(class HTTPAPIHANDLE *HTTPHandle,httpdata *request);
	void Disconnect(void);

	/*************/
	//Funciones para proxy
	struct httpdata *ReadHTTPProxyRequestData();	
	struct httpdata *ReadHTTPResponseData(class ConnectionHandling *ProxyClientConnection, httpdata* request,class Threading *ExternalMutex);
	void Acceptdatasock( SOCKET ListenSocket )
	{
		int clientLen= sizeof(struct sockaddr_in);
		datasock= (int) accept(ListenSocket,(struct sockaddr *) &webserver,(socklen_t *)&clientLen);
		target=webserver.sin_addr.s_addr;
		strcpy(targetDNS,inet_ntoa(webserver.sin_addr));		
		id++;
	}
	void CloseSocket() { closesocket(datasock); }
	char *GettargetDNS() { return targetDNS; }
	/*************/

	long GetTarget() { return target; }
	int  GetPort() { return(port); }
	int  GetThreadID() { return ThreadID; }
	unsigned int Getio() { return io;}
	void Setio(unsigned int value) { io = value; }
	int GetPENDINGPIPELINEREQUESTS() { return PENDING_PIPELINE_REQUESTS; }
	unsigned long *GetPIPELINERequestID() { return PIPELINE_Request_ID; }
	int GetConnectionAgainstProxy() { return ConnectionAgainstProxy; }

	void UpdateLastConnectionActivityTime(void)
	{
	#ifdef __WIN32__RELEASE__
		GetSystemTimeAsFileTime (&tlastused);
	#else
		time(&tlastused);
	#endif
    }

	#ifdef _OPENSSL_SUPPORT_
	void *IsSSLInitialized() { return (void*)ssl; }	
	void SetBioErr(void *bio)
	{
		bio_err = (BIO*)bio;
	}

	void SetCTX(void *proxyctx);
	#else
	void *IsSSLInitialized() { return(NULL); }

	#endif


};






#endif