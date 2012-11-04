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

/** \file HTTPHeaders.cpp
 * Fast HTTP Auth Scanner - HTTP Engine v1.4.
 * ..
 * \author Andres Tarasco Acuna - http://www.tarasco.org
 *
 */
#include "HTTPHeaders.h"
#include "HTTP.h"

HTTPHeaders::HTTPHeaders() {
	Header = NULL;
	HeaderSize = 0;

}
//-----------------------------------------------------------------------------
 HTTPHeaders::~HTTPHeaders()
 {
 if (Header)
 {
 free(Header);
 Header = NULL;
 }
 HeaderSize = 0;
 }
//-----------------------------------------------------------------------------
#ifdef UNICODE

void HTTPHeaders::InitHTTPHeaders(char* header, size_t length) {
	if (header) {
		if (Header) /* delete old headers */ {
			free(Header);
			Header = NULL;
			HeaderSize = 0;
		}
		/* Unicode conversion */
		HeaderSize = MultiByteToWideChar(CP_UTF8, 0, header, length, NULL, 0);
		if (HeaderSize) {
			// _tprintf(_T("Source Buffer: %i bytes - Destination %i bytes\n"),length,HeaderSize);
			Header = (wchar_t*)malloc((HeaderSize + 1)*sizeof(HTTPCHAR));
			if (Header) /* Validate allocation */ {
				MultiByteToWideChar(CP_UTF8, 0, header, length, Header,
					HeaderSize);
				Header[HeaderSize] = 0;
			}
		}
	}
}
#endif
//-----------------------------------------------------------------------------
 void HTTPHeaders::InitHTTPHeaders(HTTPCSTR header, size_t length)
 {
 if (header)
 {
 if (Header) /* delete old headers */ {
	free(Header);
	Header = NULL;
	HeaderSize = 0;
} Header = (HTTPCHAR*)malloc((length + 1)*sizeof(HTTPCHAR));
if (Header) {
	memcpy(Header, header, length*sizeof(HTTPCHAR));
	Header[length] = 0;
	HeaderSize = length;
}
}}

//-----------------------------------------------------------------------------
 void HTTPHeaders::InitHTTPHeaders(HTTPCSTR header)
 {
 if ( header )
 {
 InitHTTPHeaders(header,_tcslen(header));
 }
 }
//-----------------------------------------------------------------------------
HTTPCHAR* HTTPHeaders::GetHeaderValueByID(unsigned int id) {

HTTPCHAR *base, *end;
base = end = Header;

if (Header) {
while (*end) {
	if (*end == _T('\n')) {
		if (id == 0) {
			if ((end - base) <= sizeof(HTTPCHAR)) {
				return (NULL);
			}
			HTTPCHAR *p = (HTTPCHAR*) malloc((end - base + 1)*sizeof(HTTPCHAR));
			// HTTPCHAR *p = new HTTPCHAR[end - base +1];
			if (!p) {
				// Retry once again. Sometimes this call fails :?
				p = (HTTPCHAR*) malloc((end - base + 1)*sizeof(HTTPCHAR));
				if (!p) {
					return (NULL);
				}
			}
			memcpy(p, base, (end - base)*sizeof(HTTPCHAR));
			p[end - base] = 0;
			if (p[end - base - 1] == _T('\r'))
				p[end - base - 1] = 0;
			return (p);
		}
		id--;
		base = end + 1;
	}
	end++;
}
}
return (NULL);
}

//-----------------------------------------------------------------------------
 HTTPCHAR* HTTPHeaders::AddHeader(HTTPCSTR newheader)
 {
 if (!newheader)  //safety check.
 {
 return(NULL);
 }

 if (!HeaderSize)
 {   /* First HTTP Header */
int CLRFNeeded = 0;
size_t l = _tcslen(newheader);
if (memcmp(newheader + l - 2, _T("\r\n"), 2*sizeof(HTTPCHAR)) != 0)
CLRFNeeded += 2;
if (memcmp(newheader + l - 4, _T("\r\n"), 2*sizeof(HTTPCHAR)) != 0)
CLRFNeeded += 2;
Header = (HTTPCHAR*)realloc(Header, (l + CLRFNeeded + 1)*sizeof(HTTPCHAR));
memcpy(Header, newheader, l*sizeof(HTTPCHAR));
HeaderSize = l + CLRFNeeded;
if (CLRFNeeded) {
memcpy(Header + l, _T("\r\n"), 2*sizeof(HTTPCHAR));
CLRFNeeded -= 2;
}
if (CLRFNeeded) {
memcpy(Header + l + 2, _T("\r\n"), 2*sizeof(HTTPCHAR));
CLRFNeeded -= 2;
}
}
else {
size_t NewSize = _tcslen(newheader);
int CLRFNeeded = 0;

if (newheader[NewSize - 1] != _T('\n'))
CLRFNeeded = 2;

size_t newHeaderSize = (HeaderSize + NewSize + CLRFNeeded + 1)*sizeof(HTTPCHAR);
Header = (HTTPCHAR*)realloc(Header, newHeaderSize);
if (Header) {
memcpy(Header + HeaderSize - 2, newheader, NewSize*sizeof(HTTPCHAR));
if (CLRFNeeded) // Append CLRF to the header
{
memcpy(Header + HeaderSize - 2 + NewSize, _T("\r\n"), 2*sizeof(HTTPCHAR));
}
memcpy(Header + HeaderSize - 2 + CLRFNeeded + NewSize, _T("\r\n"),
	2*sizeof(HTTPCHAR));
HeaderSize += NewSize + CLRFNeeded;
}
else {

}
}
if (Header)
Header[HeaderSize] = _T('\0');
return (Header);

}
//-----------------------------------------------------------------------------
 HTTPCHAR * HTTPHeaders::RemoveHeader(HTTPCSTR oldheader)
 {
 HTTPCHAR *base,*end;
 base = end=Header;

 if ( (HeaderSize) && (Header) && (oldheader) )
 {
 size_t HeaderLen= _tcslen(oldheader);
 while (*end) {
 if (*end==_T('\n'))
 {
 if (_tcsncicmp(base,oldheader,HeaderLen)==0)
 {
 end=_tcschr(base,_T('\n'));
/*TODO: Revisar.. */
memcpy(Header + (base - Header), end + 1,
	(_tcslen(end + 1) + 1)*sizeof(HTTPCHAR));
Header = (HTTPCHAR*)realloc(Header, (HeaderSize - (end - base + 1) + 1)*sizeof
	(HTTPCHAR));
HeaderSize = _tcslen(Header);
break;
} base = end + 1;
} end++;
}} return (Header);
}
//-----------------------------------------------------------------------------
 HTTPCHAR* HTTPHeaders::GetHeaderValue(HTTPCSTR value,int n)
 {
 HTTPCHAR *base,*end;
 end=base=Header;
 if ( (Header) && (value) )
 {
 size_t valuelen=  _tcslen(value);
 while (*end)
 {
 if (*end==_T('\n'))
 {
 if (_tcsncicmp(base,value,valuelen)==0)
 {
 if (n==0)
 {
 base  = base + valuelen;
 while  (( *base==_T(' ')) || (*base==_T(':') ) )  { base++; }
 size_t len =  (end-base);
 HTTPCHAR *header=(HTTPCHAR*)malloc((len+1)*sizeof(HTTPCHAR));
 if (header) {
 memcpy(header,base,len*sizeof(HTTPCHAR));
 if (header[len-1]==_T('\r'))
 {
 header[len-1]=_T('\0');
 } else {
 header[len]=_T('\0');
 }
 return (header);
 } else {
 return(NULL);
 }
 } else
 {
 n--;
 }
 }
 base=end+1;
 }
 end++;
 }
 }
 return(NULL);
 }

//-----------------------------------------------------------------------------

HTTPCHAR* HTTPHeaders::GetHeaders(void) {
return (Header);

}

//-----------------------------------------------------------------------------
 size_t HTTPHeaders::GetHeaderSize(void)
 {
 return (HeaderSize);
 }
//-----------------------------------------------------------------------------
const HTTPSTR HTTPHeaders::Headerstrstr(HTTPCSTR searchdata) {
if ((Header) && (HeaderSize)) {
return (_tcsstr(Header, searchdata));
}
return (NULL);
}
//-----------------------------------------------------------------------------
