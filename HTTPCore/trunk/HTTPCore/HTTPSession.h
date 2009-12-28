#ifndef __HTTP_SESSION_H_
#define __HTTP_SESSION_H_

#include "HTTPRequest.h"
#include "HTTPResponse.h"

/*!\STRUCT HTTPSession*
  \brief This struct handles information related to and http response and includes information about client request, server response, url, server version .returned by an HTTP Server
*/
struct HTTPSession {
public:
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
   HTTPRequest* request;
   /*!< Information related to the HTTP Request. This struct contains both client headers and postdata */
   HTTPResponse* response;
   /*!< Information related to the HTTP response. This struct contains both server headers and data */
   HTTPSTR server;
   /*!< pointer to a string that contains the server banner from the remote http server */
   HTTPCHAR Method[20];
   /*!< HTTP Verb used */
   unsigned int status;
   /*!< status code returned by the HTTP server. Example: "200", for an STATUS OK response. */
   HTTPSTR ContentType;
   /*!< Response Content-Type */

	HTTPSession();
	~HTTPSession();
   int IsValidHTTPResponse(void);
   int HasResponseHeader(void);
   int HasResponseData(void);
   void ParseReturnedBuffer(HTTPRequest* HTTPrequest, HTTPResponse* HTTPresponse);} ;


#endif

