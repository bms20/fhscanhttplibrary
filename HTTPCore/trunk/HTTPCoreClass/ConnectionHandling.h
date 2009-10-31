#ifndef __CONNECTIONHANDLING_H__
#define __CONNECTIONHANDLING_H__

#include "Build.h"
#include "Threading.h"
#include "HTTPHANDLE.h"
#include "HTTP.h"
#include "FileMapping.h"

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
 #include <openssl/crypto.h>
 #include <openssl/x509.h>
 #include <openssl/pem.h>
 #include <openssl/ssl.h>
 #include <openssl/err.h>
 #define SSL_CTX_SET_TMP_DH(ctx,dh) \
    	 SSL_CTX_CTRL(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)dh)
 #ifdef __WIN32__RELEASE__
	typedef SSL*        (*SSL_NEW_FUNC)(SSL_CTX*);        
	typedef void        (*SSL_FREE_FUNC)(SSL*);
	typedef int         (*SSL_SHUTDOWN_FUNC)(SSL*);
    typedef int         (*SSL_READ_FUNC)(SSL*,void*,int);
    typedef int         (*SSL_WRITE_FUNC)(SSL*,const void*,int);
    typedef void        (*SSL_CTX_FREE_FUNC)(SSL_CTX*);             
	typedef SSL_CTX*    (*SSL_CTX_NEW_FUNC) (SSL_METHOD*);
    typedef int         (*SSL_CONNECT_FUNC)(SSL*);
	typedef int			(*SSL_GET_ERROR_FUNC) (SSL*,int);
	typedef int         (*SSL_SET_FD_FUNC)(SSL*,int);
	typedef int			(*SSL_PENDING_FUNC)(SSL*);
	typedef SSL_METHOD* (*TLSV1_CLIENT_METHOD_FUNC)(void);
	typedef void		(*SSL_LOAD_ERROR_STRINGS_FUNC)(void);
	typedef int			(*SSL_LIBRARY_INIT_FUNC)(void);
	

	typedef SSL_METHOD* (*SSLV23_METHOD_FUNC)(void);
	typedef void		(*SSL_CTX_SET_DEFAULT_PASSWD_CB_FUNC)(SSL_CTX*,pem_password_cb*);
	typedef int			(*SSL_ACCEPT_FUNC)(SSL*);
	typedef int			(*SSL_CTX_LOAD_VERIFY_LOCATIONS_FUNC)(SSL_CTX*,const char*, const char *);
	typedef BIO*		(*BIO_NEW_FILE_FUNC)(const char*, const char*);	
	typedef int			(*SSL_CTX_USE_CERTIFICATE_CHAIN_FILE_FUNC)(SSL_CTX*,const char*);
	typedef BIO*		(*BIO_NEW_SOCKET_FUNC)(int, int);
	typedef int			(*BIO_FREE_FUNC) (BIO*);
	typedef BIO*		(*BIO_NEW_FP_FUNC)(FILE*,int);
	typedef void		(*SSL_SET_BIO_FUNC) (SSL*,BIO*,BIO*);
	typedef int			(*SSL_CTX_USE_PRIVATEKEY_FILE_FUNC)(SSL_CTX*,const char*,int);
	typedef long		(*SSL_CTX_CTRL_FUNC) (SSL_CTX *,int , long , void *);
	typedef void		(*SSL_CTX_SET_VERIFY_DEPTH_FUNC)(SSL_CTX *,int);
	typedef DH*			(*PEM_READ_BIO_DHPARAMS_FUNC) (BIO*, DH**,int*,void*);



    extern SSL_NEW_FUNC                SSL_NEW;
	extern SSL_FREE_FUNC               SSL_FREE;
    extern SSL_SHUTDOWN_FUNC           SSL_SHUTDOWN;
    extern SSL_READ_FUNC               SSL_READ;
	extern SSL_WRITE_FUNC              SSL_WRITE;
    extern SSL_CTX_FREE_FUNC           SSL_CTX_FREE;		
    extern SSL_CTX_NEW_FUNC            SSL_CTX_NEW;
	extern SSL_CONNECT_FUNC            SSL_CONNECT;
	extern SSL_GET_ERROR_FUNC		   SSL_GET_ERROR;
	extern SSL_SET_FD_FUNC             SSL_SET_FD;
	extern SSL_PENDING_FUNC			   SSL_PENDING;
	extern TLSV1_CLIENT_METHOD_FUNC    TLSV1_CLIENT_METHOD;		
	extern SSL_LOAD_ERROR_STRINGS_FUNC SSL_LOAD_ERROR_STRINGS;
	extern SSL_LIBRARY_INIT_FUNC	   SSL_LIBRARY_INIT;
	
	extern SSLV23_METHOD_FUNC		   SSLV23_METHOD;
	extern SSL_CTX_SET_DEFAULT_PASSWD_CB_FUNC	SSL_CTX_SET_DEFAULT_PASSWD_CB;
	extern SSL_ACCEPT_FUNC				SSL_ACCEPT;
	extern SSL_CTX_LOAD_VERIFY_LOCATIONS_FUNC	SSL_CTX_LOAD_VERIFY_LOCATIONS;
	extern BIO_NEW_FILE_FUNC			BIO_NEW_FILE;
	extern SSL_CTX_USE_CERTIFICATE_CHAIN_FILE_FUNC	SSL_CTX_USE_CERTIFICATE_CHAIN_FILE;
	extern BIO_NEW_SOCKET_FUNC			BIO_NEW_SOCKET;
	extern BIO_FREE_FUNC				BIO_FREE;
	extern BIO_NEW_FP_FUNC				BIO_NEW_FP;
	extern SSL_SET_BIO_FUNC					SSL_SET_BIO;
	extern SSL_CTX_USE_PRIVATEKEY_FILE_FUNC	SSL_CTX_USE_PRIVATEKEY_FILE;
	extern SSL_CTX_CTRL_FUNC	SSL_CTX_CTRL;
	extern SSL_CTX_SET_VERIFY_DEPTH_FUNC SSL_CTX_SET_VERIFY_DEPTH;
	extern PEM_READ_BIO_DHPARAMS_FUNC		PEM_READ_BIO_DHPARAMS;
#endif
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

class ConnectionHandling {
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
	int				GetConnection(class HHANDLE *HTTPHandle);	
	int				SendHTTPRequest(httpdata* request);
	
	httpdata		*SendAndReadHTTPData(class HHANDLE *HTTPHandle,httpdata *request);
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
	void *IsSSLInitialized() { return(0); }

	#endif


};






#endif