/*
#include "HTTPData.h"
#include <stdio.h>
*/
/*******************************************************************************************************/

/*******************************************************************************************************/

#if 0

/*******************************************************************************************************/


/*******************************************************************************************************/
#ifdef UNICODE
void httpdata::InitHTTPDataA(char* header,size_t headersize, char* lpPostData,size_t PostDataSize)
{
	if ( (headersize) && (header) )
	{
		Header= (HTTPSTR)malloc((headersize+1)*sizeof(HTTPCHAR));
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
		Data= (HTTPCHAR*)malloc((PostDataSize+1)*sizeof(HTTPCHAR));
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
		Header= (HTTPCHAR*)malloc((headersize+1)*sizeof(HTTPCHAR));
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
		Data= (HTTPCHAR*)malloc(PostDataSize*sizeof(HTTPCHAR)+1);
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
httpdata::httpdata(HTTPCSTR header)	 
{  
	InitHTTPData(header,_tcslen(header),NULL,0); 
}

httpdata::httpdata(HTTPCSTR header, size_t  headersize)   
{	
	InitHTTPData(header,headersize,NULL,0); 
}

httpdata::httpdata(HTTPCSTR header, HTTPCSTR lpPostData) 
{	
	InitHTTPData(header,_tcslen(header),lpPostData,_tcslen(lpPostData)); 
}

httpdata::httpdata(HTTPCSTR header,size_t headersize, HTTPCSTR lpPostData,size_t  PostDataSize) 
{ 
	InitHTTPData(header,headersize,lpPostData,PostDataSize); 
}
/*
#ifdef UNICODE
httpdata::httpdata(HTTPCSTR header, char* lpPostData) 
{	
	InitHTTPData(header,_tcslen(header),lpPostData,strlen(lpPostData)); 
}

httpdata::httpdata(HTTPCSTR header,size_t headersize, HTTPCSTR lpPostData,size_t  PostDataSize) 
{ 
	InitHTTPData(header,headersize,lpPostData,PostDataSize); 
}
#endif
*/
/*******************************************************************************************************/
void httpdata::InitHTTPData(HTTPCSTR header) 
{	
	InitHTTPData(header,_tcslen(header),NULL,0); 
}
void httpdata::InitHTTPData(HTTPCSTR header, size_t headersize) 
{	
	InitHTTPData(header,headersize,NULL,0); 
}
void httpdata::InitHTTPData(HTTPCSTR header, HTTPCSTR lpPostData) 
{	
	InitHTTPData(header,_tcslen(header),lpPostData,_tcslen(lpPostData)); 
}
/*******************************************************************************************************/
/*
#ifdef UNICODE
httpdata::httpdata(char* header, size_t  headersize)   {	InitHTTPData(header,headersize,NULL,0); }
#endif
*/
/*******************************************************************************************************/

/*******************************************************************************************************/
/*
It is the responsibility of the calling application to free the allocated memory.
*/
/*******************************************************************************************************/
int httpdata::GetnComments()
{
	return (nComments);
}
/*******************************************************************************************************/
int httpdata::AddComment(HTTPCHAR *lpComment)
{
	if (nComments==0)
	{
		Comments=(HTTPCHAR**)malloc(sizeof(HTTPCHAR*));
	} else 
	{
		Comments=(HTTPCHAR**)realloc(Comments,sizeof(HTTPCHAR*)*(nComments+1));
	}
	Comments[nComments]=_tcsdup(lpComment);
	nComments++;
	return(nComments);
}
/*******************************************************************************************************/
HTTPCHAR *httpdata::GetComment(int i)
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
int httpdata::AddUrlCrawled(HTTPCHAR *lpComment, HTTPCHAR *tagtype)
{
	for(int i=0;i<nUrlCrawled;i++)
	{
		if (_tcscmp(UrlCrawled[i],lpComment)==0)
		{
			return(0);
		}
	}
	if (nUrlCrawled==0)
	{
		UrlCrawled=(HTTPCHAR**)malloc(sizeof(HTTPCHAR*));
		linktagtype=(HTTPCHAR**)malloc(sizeof(HTTPCHAR*));
	} else 
	{
		UrlCrawled=(HTTPCHAR**)realloc(UrlCrawled,sizeof(HTTPCHAR*)*(nUrlCrawled+1));
		linktagtype=(HTTPCHAR**)realloc(linktagtype,sizeof(HTTPCHAR*)*(nUrlCrawled+1));
	}
	UrlCrawled[nUrlCrawled]=_tcsdup(lpComment);
	linktagtype[nUrlCrawled]=_tcsdup(tagtype);
	nUrlCrawled++;
	return(nUrlCrawled);
}
/*******************************************************************************************************/
HTTPCHAR *httpdata::GetUrlCrawled(int i)
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
HTTPCHAR *httpdata::GettagCrawled(int i)
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


/*******************************************************************************************************/


/*******************************************************************************************************/

/*******************************************************************************************************/

#endif