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

	/* Initicialización */
	httpdata();
	httpdata(const char *header);
	httpdata(const char *header, int headersize);
	httpdata(const char *header, const char *lpPostData);
	httpdata(const char *header,unsigned int headersize, const char *lpPostData,unsigned int PostDataSize);
	void InitHTTPData(const char *header,unsigned int headersize, const char *lpPostData,unsigned int PostDataSize);
	void InitHTTPData(const char *header);
	void InitHTTPData(const char *header, int headersize);
	void InitHTTPData(const char *header, const char *lpPostData);
	~httpdata();

	/* Manipulación de cabeceras */
	char *GetHeaderValue(const char *value,int n);
	char *GetHeaderValueByID(unsigned int id);
	char *AddHeader(const char *Header);
	char *RemoveHeader(const char *Header);	
	char* BuildHTTPProxyResponseHeader( int isSSLStablished,int closeconnection, int status, const char *protocol,const char* title, const char* extra_header, const char* mime_type, int length, time_t mod );

	/* Obtención de Información de las respuestas */
	char			*GetServerVersion();
	int 			 GetStatus();
	char			*GetRequestedURL();
	char			*GetHTTPMethod();
	enum AuthenticationType IschallengeSupported(const char *AuthNeeded);

	/*FileMapping */
	HTTPIOMapping *GetHTTPIOMappingData() {
		if (!HTTPIOMappingData) HTTPIOMappingData = new HTTPIOMapping;
		return HTTPIOMappingData;
	}
	void UpdateAndReplaceFileMappingData(HTTPIOMapping *newFileMapping);

	/* Spider */
	int GetnComments();
	int AddComment(char *lpComment);
	char *GetComment(int i);
	int GetnUrlCrawled();
	int AddUrlCrawled(char *lpComment, char *tagtype);
	char *GetUrlCrawled(int i);
	char *GettagCrawled(int i);

	char *Datastrstr  (const char *searchdata);
	char *Headerstrstr(const char *searchdata);
};

typedef int HTTPHANDLE;


#endif
