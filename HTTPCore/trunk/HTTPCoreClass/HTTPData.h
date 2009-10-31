#ifndef __HTTPDATA_H__
#define __HTTPDATA_H__
#include "FileMapping.h"




/*
typedef struct crawledURL{

	int HTTPMethodGET; //Example: 1 for GET or 0 POST
	char tagname[20];
	char paramname[20];
	char description[100]; //something like title.
	char *url;
} CRAWLED;
*/

/*!\struct HTTP_DATA
  \brief An HTTP_DATA struct stores the information generated with an HTTP request or an HTTP response.\n
  If the data is related to an HTTP request, this struct will store the browser request headers and optional Post data.\n
  If the data is related to an HTTP response, this struct will store the HTTP server response headers and HTTP data.
*/

typedef struct httpdata {

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



} HTTP_DATA, *PHTTP_DATA;

typedef int HTTPHANDLE;


#endif
