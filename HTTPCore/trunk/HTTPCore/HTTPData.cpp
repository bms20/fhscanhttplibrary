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
#include "HTTPData.h"
#include <stdio.h>


/*******************************************************************************************************/


/*******************************************************************************************************/
#ifdef UNICODE
void httpdata::InitHTTPDataA(char* header,size_t headersize, char* lpPostData,size_t PostDataSize)
{
	if ( (headersize) && (header) )
	{
		Header= (HTTPSTR)malloc(headersize+1);
		MultiByteToWideChar(CP_ACP, 0, header, -1, Header, headersize+1);
		Header[headersize]='\0';
		HeaderSize = headersize;
	}  else
	{
		Header = NULL;
		HeaderSize = 0;
    }
	if ( (PostDataSize ) && (lpPostData) )
	{
		Data= (char*)malloc(PostDataSize+1);
		memcpy(Data,lpPostData,PostDataSize);
		Data[PostDataSize]='\0';
		DataSize = PostDataSize;
	} else
	{
		Data = NULL;
		DataSize = 0;
    }
	HTTPIOMappingData = NULL;	
	nUrlCrawled = 0;
	UrlCrawled = NULL;
	linktagtype = NULL;
	nComments = 0;
	Comments = NULL;
}
#endif
/*******************************************************************************************************/
void httpdata::InitHTTPData(HTTPCSTR header,size_t headersize, HTTPCSTR lpPostData,size_t PostDataSize)
{
	if ( (headersize) && (header) )
	{
		Header= (char*)malloc(headersize+1);
		memcpy(Header,header,headersize);
		Header[headersize]='\0';
		HeaderSize = headersize;
	}  else
	{
		Header = NULL;
		HeaderSize = 0;
    }
	if ( (PostDataSize ) && (lpPostData) )
	{
		Data= (char*)malloc(PostDataSize+1);
		memcpy(Data,lpPostData,PostDataSize);
		Data[PostDataSize]='\0';
		DataSize = PostDataSize;
	} else
	{
		Data = NULL;
		DataSize = 0;
    }
	HTTPIOMappingData = NULL;	
	nUrlCrawled = 0;
	UrlCrawled = NULL;
	linktagtype = NULL;
	nComments = 0;
	Comments = NULL;
}
/*******************************************************************************************************/
httpdata::httpdata()								 
{	
	Header = NULL; 
	Data = NULL; 
	HeaderSize= 0; 
	DataSize=0; 
	HTTPIOMappingData = NULL;
	nUrlCrawled = 0;
	UrlCrawled = NULL;
	linktagtype = NULL;
	nComments = 0;
	Comments = NULL;
}
/*******************************************************************************************************/
httpdata::httpdata(HTTPCSTR header)	 {  InitHTTPData(header,strlen(header),NULL,0); }
httpdata::httpdata(HTTPCSTR header, size_t  headersize)   {	InitHTTPData(header,headersize,NULL,0); }
httpdata::httpdata(HTTPCSTR header, HTTPCSTR lpPostData) {	InitHTTPData(header,strlen(header),lpPostData,strlen(lpPostData)); }
httpdata::httpdata(HTTPCSTR header,size_t headersize, HTTPCSTR lpPostData,size_t  PostDataSize) { InitHTTPData(header,headersize,lpPostData,PostDataSize); }
/*******************************************************************************************************/
void httpdata::InitHTTPData(HTTPCSTR header) {	InitHTTPData(header,strlen(header),NULL,0); }
void httpdata::InitHTTPData(HTTPCSTR header, size_t headersize) {	InitHTTPData(header,headersize,NULL,0); }
void httpdata::InitHTTPData(HTTPCSTR header, HTTPCSTR lpPostData) {	InitHTTPData(header,strlen(header),lpPostData,strlen(lpPostData)); }
/*******************************************************************************************************/
/*
#ifdef UNICODE
httpdata::httpdata(char* header, size_t  headersize)   {	InitHTTPData(header,headersize,NULL,0); }
#endif
*/
/*******************************************************************************************************/

HTTPSTR httpdata::GetRequestedURL()
{
	char *p = Header;
	int len=0;
	if (Header)
	{
		
		while ( (*p) && (*p!=' '))  { p++; }
		p++;
		char *q=p;
		while (*q)
		{
			if ( (*q==' ') || (*q=='?') || (*q=='&') || (*q=='\r') || (*q=='\n') )
			//if ( (*q==' ') || (*q=='\r') || (*q=='\n') )
			break;
			len++; q++;
		}
	}
	char *requestedurl = (char*) malloc(len+1);
	memcpy(requestedurl,p,len);
	requestedurl[len]=0;
	return(requestedurl);
}
/*******************************************************************************************************/
/*
It is the responsibility of the calling application to free the allocated memory.
*/
/*******************************************************************************************************/
HTTPSTR httpdata::GetHeaderValueByID(unsigned int id)
{

	char *base, *end;
	base = end=Header;

	if (Header)
	{
		while (*end)
		{
			if  (*end=='\n')
			{
				if (id==0)
				{
					if ( (end - base)<=1) {
						return(NULL);
					}
					char *p=(char *) malloc(end - base +1);
					memcpy(p,base,end-base);
					p[end-base]='\0';
					if (p[end-base-1]=='\r')
						p[end-base-1]='\0';
					return(p);
				}
				id--;
				base=end+1;
			}
			end++;
		}
	}
	return (NULL);
}

/*******************************************************************************************************/
HTTPSTR httpdata::AddHeader(HTTPCSTR newheader)
{
	if (!newheader)  //safety check.
	{
		return(NULL);
	}
	if (!HeaderSize)
	{
		int CLRFNeeded = 0;
		size_t l = strlen(newheader);
		if (memcmp(newheader + l -2,"\r\n",2)!=0) CLRFNeeded+=2;
		if (memcmp(newheader + l -4,"\r\n",2)!=0) CLRFNeeded+=2;		
		Header = (char*)realloc(Header,l+CLRFNeeded+1);		
		memcpy(Header,newheader,l);	
		HeaderSize =l + CLRFNeeded;
		if (CLRFNeeded)
		{
			memcpy(Header+l,"\r\n",2);
			CLRFNeeded-=2;
		}
		if (CLRFNeeded)
		{
			memcpy(Header+l+2,"\r\n",2);
			CLRFNeeded-=2;
		}
	} 
	else
	{
		size_t NewSize=  strlen(newheader);
		int CLRFNeeded = 0;

		if (newheader[NewSize-1] != '\n') CLRFNeeded = 2;

		Header=(char*)realloc(Header, HeaderSize + NewSize + CLRFNeeded +1);
		if (!Header) //safety check.
		{
			return(NULL);
		}
		memcpy(Header + HeaderSize -2, newheader,NewSize);
		if (CLRFNeeded) //Append CLRF to the header
		{
			memcpy(Header + HeaderSize -2 + NewSize,"\r\n",2);
		}
		memcpy(Header + HeaderSize -2 + CLRFNeeded + NewSize,"\r\n",2);
		HeaderSize+=NewSize + CLRFNeeded;
	}
	Header[HeaderSize]='\0';
	return(Header);


}
/*******************************************************************************************************/
char * httpdata::RemoveHeader(HTTPCSTR oldheader)
{
	char *base,*end;
	base = end=Header;

	if ( (HeaderSize) && (Header) && (oldheader) )
	{
		size_t HeaderLen= strlen(oldheader);
		while (*end) {
			if (*end=='\n')
			{
				if (strnicmp(base,oldheader,HeaderLen)==0)
				{
					end=strchr(base,'\n');
					memcpy(Header + (base - Header),end+1,strlen(end+1)+1);
					Header=(char *)realloc(Header,HeaderSize - (end - base +1) +1 );
					HeaderSize = strlen(Header);
					break;
				}
				base=end+1;
			}
			end++;
		}
	}
	return(Header);
}
/*******************************************************************************************************/
int httpdata::GetnComments()
{
	return (nComments);
}
/*******************************************************************************************************/
int httpdata::AddComment(char *lpComment)
{
	if (nComments==0)
	{
		Comments=(char**)malloc(sizeof(char*));
	} else 
	{
		Comments=(char**)realloc(Comments,sizeof(char*)*(nComments+1));
	}
	Comments[nComments]=_tcsdup(lpComment);
	nComments++;
	return(nComments);
}
/*******************************************************************************************************/
char *httpdata::GetComment(int i)
{
	if (i>=nComments) 
	{
		return(NULL);
	} else 
	{
		return (Comments[i]);
	}
}
/*******************************************************************************************************/
int httpdata::GetnUrlCrawled()
{
	return (nUrlCrawled);
}
/*******************************************************************************************************/
int httpdata::AddUrlCrawled(char *lpComment, char *tagtype)
{
	for(int i=0;i<nUrlCrawled;i++)
	{
		if (strcmp(UrlCrawled[i],lpComment)==0)
		{
			return(0);
		}
	}
	if (nUrlCrawled==0)
	{
		UrlCrawled=(char**)malloc(sizeof(char*));
		linktagtype=(char**)malloc(sizeof(char*));
	} else 
	{
		UrlCrawled=(char**)realloc(UrlCrawled,sizeof(char*)*(nUrlCrawled+1));
		linktagtype=(char**)realloc(linktagtype,sizeof(char*)*(nUrlCrawled+1));
	}
	UrlCrawled[nUrlCrawled]=_tcsdup(lpComment);
	linktagtype[nUrlCrawled]=_tcsdup(tagtype);
	nUrlCrawled++;
	return(nUrlCrawled);
}
/*******************************************************************************************************/
char *httpdata::GetUrlCrawled(int i)
{
	if (i>=nUrlCrawled)
	{
		return(NULL);
	} else
	{
		return (UrlCrawled[i]);
	}
}
/*******************************************************************************************************/
char *httpdata::GettagCrawled(int i)
{
	if (i>=nUrlCrawled)
	{
		return(NULL);
	} else
	{
		return (linktagtype[i]);
	}
}

/*******************************************************************************************************/
httpdata::~httpdata()
{ 
		if (HTTPIOMappingData)
		{
			if (HTTPIOMappingData->IsAssigned())
			{
				if (HTTPIOMappingData->GetMappingData() != Data)
				{
					if (Data)	free(Data);
				} 
				delete HTTPIOMappingData;
			} else 
			{
				if (Data)	free(Data);
			}
		} else {
			if (Data)	free(Data);
		}
		
		if (Header) free(Header);
		DataSize =0;
		HeaderSize=0;
		if (nUrlCrawled)
		{
			for(int i=0;i<nUrlCrawled;i++)
			{
				free(UrlCrawled[i]);
				free(linktagtype[i]);
			}
			free(UrlCrawled);
			free(linktagtype);
			nUrlCrawled = 0;
			UrlCrawled = NULL;
		}
		if (nComments)
		{
			for(int i=0;i<nComments;i++)
			{
				free(Comments[i]);
			}
			free(Comments);
			nComments = 0;
			Comments = NULL;
		}
}
/*******************************************************************************************************/
HTTPSTR httpdata::GetHeaderValue(HTTPCSTR value,int n)
{
	HTTPCHAR *base,*end;
	end=base=Header;
	if ( (Header) && (value) )
	{
		size_t valuelen=  strlen(value);
		while (*end) 
		{
			if (*end==_T('\n'))
			{
				if (strnicmp(base,value,valuelen)==0)
				{
					if (n==0)
					{
						base  = base + valuelen;
						while  (( *base==_T(' ')) || (*base==_T(':') ) )  { base++; }
						size_t len =  (end-base);
						char *header=(char*)malloc(len+1);
						memcpy(header,base,len);
						if (header[len-1]==_T('\r'))
						{
							header[len-1]=_T('\0');
						} else {
							header[len]=_T('\0');
						}
						return (header);
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


/*******************************************************************************************************/
HTTPSTR httpdata::GetServerVersion()
{
	HTTPCHAR *server=NULL;
	if ((Header) && (HeaderSize) )
	{
		server = GetHeaderValue(_T("Server: "),0);
	}
	return( server ? server :_tcsdup(_T("HTTP/1.0")) );
}

/*******************************************************************************************************/
void httpdata::UpdateAndReplaceFileMappingData(HTTPIOMapping *newFileMapping)
	{
		if (HTTPIOMappingData)
		{
			if (Data == HTTPIOMappingData->GetMappingData())
			{ /* previous filemapping existed , remove the filemapping however do not interact with memory*/
				Data = NULL;
				DataSize = 0;
			}
		   delete HTTPIOMappingData;
		   HTTPIOMappingData = NULL;
		} else {
			if (Data) free(Data);
			Data = NULL;
			DataSize = 0;
		}
		
		if (newFileMapping)
		{
			HTTPIOMappingData = newFileMapping;
		 	Data = HTTPIOMappingData->GetMappingData();
			if (Data == NULL)
			{
				delete HTTPIOMappingData;
				HTTPIOMappingData = NULL;
			} else
			{
				DataSize = HTTPIOMappingData->GetMappingSize();
			}
		}
	}
/*******************************************************************************************************/


/*******************************************************************************************************/

int httpdata::GetStatus()
{
		if ( (Header) && (HeaderSize>12) )
		{
			char tmp[4];
			memcpy(tmp,Header+9,3);
			tmp[3]=0;
			int ret = atoi(tmp);
			if (ret ==0)
			{
				printf("HTTP Protocol Error - Invalid HTTP header data\n");
			}
			return(atoi(tmp));
		} else {
			return(0);

		}
}
/*******************************************************************************************************/
char *httpdata::GetHTTPMethod()
{
	if ( (Header) && (HeaderSize>12) )
	{
		int len=0;
		HTTPCHAR *p=Header;
		while (*p!=_T(' '))
		{
			p++;
			len++;
		}
		if (!len) return ( NULL );
		p=(HTTPCHAR*)malloc(len+1);
		memcpy(p,Header,len);
		p[len]=_T('\0');
		return(p);
	} else {
		return(NULL);
	}

}
/*******************************************************************************************************/
char *httpdata::Datastrstr(HTTPCSTR searchdata)
{
	if ((Data) && (DataSize))
	{
		return(strstr(Data,searchdata));
	}
	return(NULL);
}
/*******************************************************************************************************/
char *httpdata::Headerstrstr(HTTPCSTR searchdata)
{
	if ((Header) && (HeaderSize))
	{
		return(strstr(Header,searchdata));
	}
	return(NULL);
}
/*******************************************************************************************************/
