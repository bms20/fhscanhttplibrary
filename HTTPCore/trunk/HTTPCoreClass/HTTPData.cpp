#include "HTTPData.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define SERVER_NAME "FSCAN HTTP Proxy"
#define RFC1123FMT  "%a, %d %b %Y %H:%M:%S GMT"


/*******************************************************************************************************/
prequest::prequest()
{
	*hostname=0;
	ip=0;
	port = 0;
	NeedSSL = 0;
	url = NULL;
	Parameters = NULL;
	request = NULL;
	response = NULL;
	server = NULL;
	*Method=0;
	status=NO_AUTH;	
	ContentType = NULL;
}
/*******************************************************************************************/
prequest::~prequest()
{	
	delete request;
	delete response;
	if (server)			free(server);
	if (ContentType)	free(ContentType);
	if (url)			free(url);
	if (Parameters)		free(Parameters);
}

int prequest::IsValidHTTPResponse(void) 
{ 
	return ((response) && (response->Header) && (response->HeaderSize) && (status>100) && (status<520) ) ; 
}

int prequest::HasResponseHeader(void) 
{ 
	return ( (response) && (response->HeaderSize) && (response->Header) ); 
}

int prequest::HasResponseData(void) 
{   
	return ( (response) && (response->DataSize) && (response->Data)   ); 
}

/*******************************************************************************************************/

/*******************************************************************************************************/
void httpdata::InitHTTPData(const char *header,unsigned int headersize, const char *lpPostData,unsigned int PostDataSize)
{
	if ( (headersize) && (header) )
	{
		Header= (char*)malloc(headersize+1);
		memcpy(Header,header,headersize);
		Header[headersize]='\0';
		HeaderSize = headersize;
	} else
	{
		Header=(char*)malloc(1);
		Header[0]='\0';
		HeaderSize=0;
	}
	if ( (PostDataSize ) && (lpPostData) )
	{
		Data= (char*)malloc(PostDataSize+1);
		memcpy(Data,lpPostData,PostDataSize);
		Data[PostDataSize]='\0';
		DataSize = PostDataSize;
	} else
	{
		Data=(char*)malloc(1);
		Data[0]='\0';
		DataSize=0;
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
httpdata::httpdata(const char *header)	 {  InitHTTPData(header,(unsigned int)strlen(header),NULL,0); }
httpdata::httpdata(const char *header, int headersize)   {	InitHTTPData(header,headersize,NULL,0); }
httpdata::httpdata(const char *header, const char *lpPostData) {	InitHTTPData(header,(unsigned int)strlen(header),lpPostData,(unsigned int)strlen(lpPostData)); }
httpdata::httpdata(const char *header,unsigned int headersize, const char *lpPostData,unsigned int PostDataSize) { InitHTTPData(header,headersize,lpPostData,PostDataSize); }
/*******************************************************************************************************/
void httpdata::InitHTTPData(const char *header) {	InitHTTPData(header,(unsigned int)strlen(header),NULL,0); }
void httpdata::InitHTTPData(const char *header, int headersize) {	InitHTTPData(header,headersize,NULL,0); }
void httpdata::InitHTTPData(const char *header, const char *lpPostData) {	InitHTTPData(header,(unsigned int)strlen(header),lpPostData,(unsigned int)strlen(lpPostData)); }
/*******************************************************************************************************/
char *httpdata::GetRequestedURL()
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
			//if ( (*q==' ') || (*q=='?') || (*q=='&') || (*q=='\r') || (*q=='\n') )
			if ( (*q==' ') || (*q=='\r') || (*q=='\n') )
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
char *httpdata::GetHeaderValueByID(unsigned int id)
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
char * httpdata::AddHeader(const char *newheader)
{
	if ((!newheader) || (!HeaderSize) ) //safety check.
	{
		return(NULL);
	}
	unsigned int NewSize= (unsigned int) strlen(newheader);
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
	Header[HeaderSize]='\0';	
	return(Header);


}
/*******************************************************************************************************/
char * httpdata::RemoveHeader(const char *oldheader)
{
	char *base,*end;
	base = end=Header;

	if ( (HeaderSize) && (Header) && (oldheader) )
	{
		unsigned int HeaderLen= (unsigned int) strlen(oldheader);
		while (*end) {
			if (*end=='\n')
			{
				if (strnicmp(base,oldheader,HeaderLen)==0)
				{
					end=strchr(base,'\n');
					memcpy(Header + (base - Header),end+1,strlen(end+1)+1);
					Header=(char *)realloc(Header,HeaderSize - (end - base +1) +1 );
					HeaderSize = (unsigned int) strlen(Header);
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
	Comments[nComments]=strdup(lpComment);
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
	UrlCrawled[nUrlCrawled]=strdup(lpComment);
	linktagtype[nUrlCrawled]=strdup(tagtype);
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
char *httpdata::GetHeaderValue(const char *value,int n)
{
	char *base,*end;
	end=base=Header;
	if ( (Header) && (value) )
	{
		unsigned int valuelen= (unsigned int) strlen(value);
		while (*end) 
		{
			if (*end=='\n')
			{
				if (strnicmp(base,value,valuelen)==0)
				{
					if (n==0)
					{
						base  = base + valuelen;
						while  (( *base==' ') || (*base==':') )  { base++; }
						unsigned int len = (unsigned int) (end-base);
						char *header=(char*)malloc(len+1);
						memcpy(header,base,len);
						if (header[len-1]=='\r')
						{
							header[len-1]='\0';
						} else {
							header[len]='\0';
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
char *httpdata::GetServerVersion()
{
	char *server=NULL;
	if ((Header) && (HeaderSize) )
	{
		server = GetHeaderValue("Server: ",0);
	}
	return( server ? server :strdup("HTTP/1.0") );
}
/*******************************************************************************************************/
enum AuthenticationType httpdata::IschallengeSupported(const char *AuthNeeded)
{
	int ret=NO_AUTH;
	int i=0;
	char *auth;

	do 
	{
		auth=GetHeaderValue(AuthNeeded,i++);
		if (auth) {
			if (strnicmp (auth, "basic",  5) == 0) {
				if (!(ret & BASIC_AUTH)) ret+=BASIC_AUTH;
			}  else
				if (strnicmp (auth, "digest", 6) == 0) {
					if (!(ret & DIGEST_AUTH)) ret+=DIGEST_AUTH;
				} else
					if (strnicmp (auth, "ntlm",   4) == 0) {
						if (!(ret & NTLM_AUTH)) ret+=NTLM_AUTH;
					} else
						if (strnicmp (auth, "Negotiate",   9) == 0) {
							if (!(ret & NTLM_AUTH)) ret+=NEGOTIATE_AUTH;
						} else {
							if (!(ret & UNKNOWN_AUTH)) ret+=UNKNOWN_AUTH;
						}
						free(auth);
		}
	} while (auth) ;
	
	if (ret != NO_AUTH)
	{
		if (ret & BASIC_AUTH) 	return(BASIC_AUTH);
		if (ret & DIGEST_AUTH) 	return(DIGEST_AUTH);
		if (ret & NTLM_AUTH) 		return(NTLM_AUTH);
		if (ret & NEGOTIATE_AUTH) return(NEGOTIATE_AUTH);
	}
	return(NO_AUTH);
	


}

/*******************************************************************************************************/
void httpdata::UpdateAndReplaceFileMappingData(HTTPIOMapping *newFileMapping)
	{
		if (HTTPIOMappingData)
		{
			if (Data == HTTPIOMappingData->GetMappingData())
			{ /* previous filemapping existed */
				Data = NULL;
				DataSize = 0;
			}
		   delete HTTPIOMappingData;
		}
		HTTPIOMappingData = newFileMapping;
		if (newFileMapping)
		{
			if (Data) free(Data);
		 	Data = newFileMapping->GetMappingData();
			if (Data == NULL)
			{
				DataSize = 0;
				delete newFileMapping;
				HTTPIOMappingData = NULL;
				/* avoid returning empty response Data */
				#if 0
				//TODO: Test if its needed.
				Data =strdup("");
				delete newFileMapping;
				HTTPIOMappingData = NULL;
				#endif
			} else
			{
				DataSize = newFileMapping->GetMappingSize();
			}
		} else {
			Data = NULL;
			DataSize = 0;
		}
	}
/*******************************************************************************************************/

char* httpdata::BuildHTTPProxyResponseHeader( int isSSLStablished,int closeconnection, int status, const char *protocol,const char* title, const char* extra_header, const char* mime_type, int length, time_t mod )
{
	time_t now;
	char timebuf[100];
	char headers[10000],tmp[10000];

	now = time( (time_t*) 0 );
	strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &now ) );
	sprintf( headers,"%s %d %s\r\nServer: %s\r\nDate: %s\r\n", protocol, status, title,SERVER_NAME,timebuf );

	if ( ( extra_header != (char*) 0 )  && (*extra_header) ) { 	sprintf(tmp, "%s\r\n", extra_header );	strcat(headers,tmp); }
	if ( mime_type != (char*) 0 ) 	{ sprintf( tmp,"Content-Type: %s\r\n", mime_type ); strcat(headers,tmp); }
	if ( length >= 0 ) 				{ sprintf(tmp, "Content-Length: %d\r\n", length );	strcat(headers,tmp); }
	if ( mod != (time_t) -1 )		{ strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &mod ) );	sprintf( tmp,"Last-Modified: %s\r\n", timebuf ); strcat(headers,tmp); }
	if (closeconnection==1)
	{
		if (isSSLStablished)		  
			sprintf( tmp,"Connection: close\r\n\r\n" );
		else
			sprintf( tmp,"Proxy-connection: close\r\n\r\n" ); 						  
		
		strcat(headers,tmp);		
	} else  { 
		strcat(headers,"\r\n"); 
	}
	InitHTTPData(headers,(unsigned int)strlen(headers),NULL,0);
	return(Header);
}
/*******************************************************************************************************/

int httpdata::GetStatus()
{
		if ( (Header) && (HeaderSize>12) )
		{
			char tmp[4];
			memcpy(tmp,Header+9,3);
			tmp[3]=0;
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
		char *p=Header;
		while (*p!=' ')
		{
			p++;
			len++;
		}
		if (!len) return ( NULL );
		p=(char*)malloc(len+1);
		memcpy(p,Header,len);
		p[len]='\0';
		return(p);
	} else {
		return(NULL);
	}

}
/*******************************************************************************************************/
char *httpdata::Datastrstr(const char *searchdata)
{
	if ((Data) && (DataSize))
	{
		return(strstr(Data,searchdata));
	}
	return(NULL);
}
/*******************************************************************************************************/
char *httpdata::Headerstrstr(const char *searchdata)
{
	if ((Header) && (HeaderSize))
	{
		return(strstr(Header,searchdata));
	}
	return(NULL);
}
/*******************************************************************************************************/
