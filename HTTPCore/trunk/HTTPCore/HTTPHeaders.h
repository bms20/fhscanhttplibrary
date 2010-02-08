#ifndef _HTTP_HEADERS_H_
#define _HTTP_HEADERS_H_

#include "Build.h"

class HTTPHeaders 
{
public:
	HTTPSTR Header;
    /*!< Pointer to a null terminated string that stores the HTTP Headers.\n 
	The data stored under this parameter can b*/	
	size_t HeaderSize;
    /*!< Size of the HTTP Headers. */

	HTTPHeaders();	
	HTTPHeaders(HTTPCSTR header);
	~HTTPHeaders();
	void InitHTTPHeaders(HTTPCSTR header);
	void InitHTTPHeaders(HTTPCSTR header, size_t length);
	#ifdef UNICODE
	void InitHTTPHeaders(char* header, size_t length);
	#endif
	const HTTPSTR Headerstrstr(HTTPCSTR searchdata);
	HTTPCHAR* GetHeaders(void);
	size_t GetHeaderSize(void);
	HTTPCHAR* GetHeaderValue(HTTPCSTR value,int n);
	HTTPCHAR* GetHeaderValueByID(unsigned int id);
	HTTPCHAR* AddHeader(HTTPCSTR Header);
	HTTPCHAR* RemoveHeader(HTTPCSTR Header);	

};

#endif
