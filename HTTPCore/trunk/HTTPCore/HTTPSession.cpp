#include "HTTPSession.h"

HTTPSession::HTTPSession() {
	*hostname = 0;
	ip = 0;
	port = 0;
	NeedSSL = 0;
	url = NULL;
	Parameters = NULL;
	request = NULL;
	response = NULL;
	server = NULL;
	*Method = 0;
	status = NO_AUTH;
	ContentType = NULL;
}

//-----------------------------------------------------------------------------
 HTTPSession::~HTTPSession()
 {
 delete request;
 delete response;
 if (server)			free(server);
 if (ContentType)	free(ContentType);
 if (url)			free(url);
 if (Parameters)		free(Parameters);
 }
//-----------------------------------------------------------------------------
int HTTPSession::IsValidHTTPResponse(void) {
	return ((response) && (response->Header) && (response->HeaderSize) &&
		(status > 100) && (status < 520));
}

//-----------------------------------------------------------------------------
 int HTTPSession::HasResponseHeader(void)
 {
 return ( (response) && (response->HeaderSize) && (response->Header) );
 }
//-----------------------------------------------------------------------------
int HTTPSession::HasResponseData(void) {
	return ((response) && (response->DataSize) && (response->Data));
}
//-----------------------------------------------------------------------------
 void HTTPSession::ParseReturnedBuffer(HTTPRequest * HTTPrequest,HTTPResponse *HTTPresponse)
 {
 request  = HTTPrequest;
 response = HTTPresponse;
 if (!response)
 {	return;
 }
 //char version[4];


 server=response->GetServerVersion();
 status = response->GetStatus();
 ContentType = request->GetHeaderValue(_T("Content-Type:"),0);

 HTTPCHAR *line = request->GetHeaderValueByID(0);
 if (line)
 {
 HTTPCHAR *p=_tcschr(line,_T(' '));
 if (p) {
 HTTPCHAR *q = _tcschr(p+1,_T(' '));
 if (q) *q=0;
 url = _tcsdup(p+1);
 *p=0;
 }
 if (url)
 {


 _tcsncpy(Method,line,sizeof(Method)/sizeof(HTTPCHAR));
 HTTPCHAR *parameters= _tcschr(url,_T('?'));
 //if (!parameters) parameters= strchr(url,';');
 if (!parameters) parameters= _tcschr(url,_T('&'));

 if (parameters)
 {
 Parameters= _tcsdup(parameters+1);
 *parameters=0;
 }
 }
 free(line);
 }
 }
