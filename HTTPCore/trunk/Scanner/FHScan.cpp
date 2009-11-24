/*
*/
#include "FHScan.h"
#include "config.h"
#include "time.h"
#include "webservers.h"
#include "RouterAuth.h"
#include "webforms.h"
#include "ProxyScanner.h"
#include "Reporting/LogSettings.h"
#include "Input/InputHosts.h"
#include <iostream>
#include <string>
using namespace std;



Threading CSip;

extern PTARGETS targets;
extern unsigned int	ntargets;
unsigned int	currenttarget = 0;

unsigned int    nthreads=9;
USERLIST        *userpass=NULL;
int             nUsers=0;
USERLOGIN	    *logins;
int             nLogins=0;
struct          _fakeauth FakeAuth[MAX_AUTH_LIST];
FILE            *ipfile=NULL;
int             FullUserList=0;
int             ShowAllhosts=0;
int             bruteforce=1;  //Yeah! try to discover default passwords
int 			VulnChecks=1;

int             nRouterAuth=0;
int				csv = 0;
extern int nvlist;
extern VLIST    vlist[200];
int     nKnownWebservers;
char    **KnownWebservers;
char	**KnownRouters;
int		nKnownRouters;
char *ipfilepath=NULL;
int TotalRequests=0;
FILE *dump = NULL;
int proxyScanOnly  = 0;


/******************************************************************************/
int IsKnownWebServer(char *server, int nKnownWebservers, char **KnownWebservers) {
	if (server)
	{
		for (int i=0;i<nKnownWebservers;i++)
		{
			if (strnicmp(server,KnownWebservers[i],strlen(KnownWebservers[i]))==0)
			{
				return(1);
			}
		}
	}
	return(0);
}
/*******************************************************************************/
int IsKnownRouter(char *server, int nKnownRouters, char **KnownRouters) {
	if (server)
	{
		for (int i=0;i<nKnownRouters;i++)
		{
			if (strnicmp(server,KnownRouters[i],strlen(KnownRouters[i]))==0)
			{
				return(1);
			}
		}
	}
	return(0);
}
/*******************************************************************************/
static long GetNextTarget(char *hostname, int dstSize, int *port, int *ssl)
{

	int ret=0;
	CSip.LockMutex();

	if (currenttarget<ntargets)
	{		
		if (targets[currenttarget].hostname) 
		{
			strncpy(hostname,targets[currenttarget].hostname,dstSize-1);
		} else {
			struct sockaddr_in ip;
			ip.sin_addr.s_addr = htonl((long)targets[currenttarget].currentip);
			strncpy(hostname,inet_ntoa(ip.sin_addr),dstSize-1);
		}
		hostname[dstSize-1]='\0';
		*port = targets[currenttarget].port;
		*ssl = targets[currenttarget].ssl;
		currenttarget++;
		ret=1;
	}
	CSip.UnLockMutex();
	return(ret);

}
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
//! This function Validates if the remote server returned a valid HTTP Response by locking to the headers and HTTP status code.
/*!
\param data Pointer to a request struct.
*/
/*******************************************************************************/
/*******************************************************************************/
void *ScanHosts(void *ptr) {
	HTTPAPI *api =(class HTTPAPI*)ptr;
	PREQUEST data;
	HTTPHANDLE HTTPHandle;//data;
	int ret;
	char hostname[512];

	int port;
	int ssl;


	while ( GetNextTarget(hostname, sizeof(hostname),&port,&ssl) )
	{
		if (!csv) {
			printf("checking %15s:%5.5i\r",hostname,port);
			fflush(stdout);
		}


		HTTPHandle=api->InitHTTPConnectionHandle(hostname,port, ssl);
		if (HTTPHandle!=INVALID_HHTPHANDLE_VALUE)
		{
			data = api->SendHttpRequest(HTTPHandle,"GET","/");
			if (
				(data) &&
				(
					(!data->IsValidHTTPResponse()) ||
					(
						(data->status==400)  &&
						(data->server)  &&
						(strcmp(data->server,"micro_httpd")==0 )
					)
				)
			   ) //Hack to detect micro_http devices that returns "400 Bad Request"
			{

				if (ShowAllhosts)
				{
					delete data;
					data = api->SendHttpRequest(HTTPHandle,"GET","//");
					if (data)
					{
						if (data->IsValidHTTPResponse())
						{
							UpdateHTMLReport(data,MESSAGE_FINGERPRINT,NULL,NULL,NULL,NULL);
						}
						delete data;
						data = NULL;
						//data=(PREQUEST)FreeRequest(data);
					}
				}
				delete data;
				data = NULL;
				//data=(PREQUEST)FreeRequest(data);
			}

			if (data)
			{
				char tmp[256];
				sprintf(tmp,"%s\n",hostname);
				if (dump)
				{
					fwrite(tmp,1,strlen(tmp),dump);
				}
				if (VulnChecks)
				{

					char *p=data->response->GetHeaderValue("Server:",0);
					if (!p) 
					{
						PREQUEST head=api->SendHttpRequest(HTTPHandle,"HEAD","/");
						if (head)
						{
							if (head->server)  
							{
								if (data->server) free (data->server);
								data->server=strdup(head->server);
							}
							delete head;
							//FreeRequest(head);
						}
					} else 
					{
						free(p);
					}

					UpdateHTMLReport(data,MESSAGE_FINGERPRINT,NULL,NULL,NULL,NULL);
					ProxyTest(api,HTTPHandle);
					if (!proxyScanOnly)
					{

						if ( IsKnownWebServer(data->server,nKnownWebservers,KnownWebservers)  && (!IsKnownRouter(data->server,nKnownRouters,KnownRouters)) ) {
							UpdateHTMLReport(data,MESSAGE_WEBSERVER_FOUND,NULL,NULL,NULL,NULL);

							ret = CheckWebformAuth(api,HTTPHandle,data,0);
							if (ret==0) CheckVulnerabilities(api,HTTPHandle,data,nUsers,userpass);


						} else { //unknown webserver. Maybe its a router
							PREQUEST auth=CheckRouterAuth(api,HTTPHandle,data,nRouterAuth, FakeAuth, nUsers, userpass);
							if (auth==NULL)
							{
								ret=CheckWebformAuth(api,HTTPHandle,data,0);
								switch (ret) 
								{
								case -1: //password not found
									UpdateHTMLReport(data,MESSAGE_ROUTER_FOUND,NULL,NULL,NULL,NULL);
									break;
								case 0: //http router authentication schema not found
									if (!IsKnownRouter(data->server,nKnownRouters,KnownRouters))  
									{
										UpdateHTMLReport(data,MESSAGE_WEBSERVER_FOUND,NULL,NULL,NULL,NULL);
										CheckVulnerabilities(api,HTTPHandle,data,nUsers,userpass);
									} else {
										UpdateHTMLReport(data,MESSAGE_ROUTER_FOUND,NULL,NULL,NULL,NULL);
										UpdateHTMLReport(data,MESSAGE_ROUTER_NOPASSWORD,NULL,NULL,NULL,NULL);
									}
									break;
								case 1: //password found
									UpdateHTMLReport(data,MESSAGE_ROUTER_FOUND,NULL,NULL,NULL,NULL);
									break;

								}
							} else {
								UpdateHTMLReport(data,MESSAGE_ROUTER_FOUND,NULL,NULL,NULL,NULL);
								delete auth;
							}
						}
					}
				}
				delete data;
				data = NULL;
			}
			api->EndHTTPConnectionHandle(HTTPHandle);
		}

	}
#ifndef __WIN32__RELEASE__
	pthread_exit(NULL);
#endif
	return NULL;

}


/*******************************************************************************/
char *Fullurl = NULL;
char *method= NULL;
char *vhost=NULL;
char *PostData = NULL;
int  PostDataSize = 0;
char *additionalheaders = NULL;
int  spider = 0;
int ShowLinks=0;
char *LinkType = NULL;
int ShowResponse = 0;

void ManualHTTPRequestMode(HTTPAPI *api)
{
	int SSLREQUEST = ( (Fullurl[4]=='s') || ( Fullurl[4]=='S') );
	int port;
	char *path = NULL;
	char *host =  Fullurl + 7 +  SSLREQUEST;
	char *p = strchr(host,':');
	char *x =strchr(host,'/');
	if  ((!p) || (p>x) ){
		if (SSLREQUEST) {
			port = 443;
		} else
		{
			port = 80;
		}
		char *newpath=strchr(host,'/');
		if (newpath) {
			path=strdup(newpath);
			*newpath=0;
		} else {
			path=strdup("/");
		}
	} else {
		*p=0;
		p++;
		char *newpath=strchr(p,'/');
		if (newpath) {
			path=strdup(newpath);
			*newpath=0;
			port = atoi(p);
		} else
		{
			port = atoi(p);
			path=strdup("/");
		}
	}

	HTTPHANDLE HTTPHandle = api->InitHTTPConnectionHandle(host,port,SSLREQUEST);
	PREQUEST data;

	if (HTTPHandle ==INVALID_HHTPHANDLE_VALUE) 
	{
		printf(" [-] Unable to resolve host: %s\n",host);
		free(path);
		return;
	}

	if (method)
	{
		data=  api->SendHttpRequest(HTTPHandle,method,path,PostData);
	} else {
		data=  api->SendHttpRequest(HTTPHandle,"GET",path,PostData);
	}


	if (data)
	{
		printf(" [+] Request: %s - port: %i - Url: %s\n",host,port,path);
		printf(" [+] Response: %i bytes \n\n%s\n",data->response->DataSize,data->response->Header);

		if (ShowLinks)
		{
			api->doSpider(host,path,data->response);
			printf(" [+] Extracted: %i links\n",data->response->GetnUrlCrawled());
			for (int i=0;i<data->response->GetnUrlCrawled(); i++)
			{
				if ( (LinkType == NULL) || (stricmp(LinkType,data->response->GettagCrawled(i))==0) )
				{
					printf("  %3.3i) %-10s %s\n",i,data->response->GettagCrawled(i),data->response->GetUrlCrawled(i));
				}

			}
			if (LinkType) {
				free(LinkType);
			}
		}
		if (ShowResponse) printf("%s\n",data->response->Data);
		delete data;
	} else 
	{
		printf(" [-] No data returned\n");
	}
    free(path);

	return;

}

/*******************************************************************************/
int CBLog(int cbType,HTTPAPI *api, HTTPHANDLE HTTPHandle, httpdata*  request, httpdata* response)
{
	if ( (request) && (response))
	{
		char *data =request->GetRequestedURL();
		int status = response->GetStatus();
		char *method =request->GetHTTPMethod();
		if (method)
		{
			printf("%-6s %-40s %.4s %3.3i %5.i %s\n",method,api->GetHTTPConfig(HTTPHandle,ConfigHTTPHost),api->GetHTTPConfig(HTTPHandle,ConfigHTTPPort),status,response->DataSize, data);
			free(method);
		}
		free(data);
	}
	return(CBRET_STATUS_NEXT_CB_CONTINUE);

}
/*******************************************************************************/
/*******************************************************************************/

void HTTPProxy(HTTPAPI *api)
{
	api->RegisterHTTPCallBack( CBTYPE_CLIENT_RESPONSE, (HTTP_IO_REQUEST_CALLBACK)CBLog,"HTTP Proxy Logger");
	api->InitHTTPProxy("127.0.0.1","8080");
	printf("[+] Proxy running. Press any key to exit\n\n");

	getchar();
	api->StopHTTPProxy();
}

/*******************************************************************************/
#ifdef __WIN32__RELEASE__
int __cdecl main(int argc, char *argv[]){
	HANDLE *thread;
#else
int main(int argc, char *argv[]){
	pthread_t *thread;
#endif

	int ret;
	HTTPAPI *api = new (HTTPAPI);
	ret = LoadConfigurationFiles( api,argc,argv);
	switch (ret) {
		case 1:
			/* Some kind of error detected */
			delete api;
			return(0);
		case 2:
			printf("HTTP Proxy Engine v1.4\n");
			printf("(c) Andres Tarasco - http://www.tarasco.org/security\n\n");
			printf("[+] Initializing HTTP/[s] Proxy Engine... \n");
			HTTPProxy(api);
			delete api;
			return(1);
		case 3:
			printf(" FHSCAN v1.4 - Manual HTTP Request\n");
			printf(" (c) Andres Tarasco - http://www.tarasco.org/security\n\n");
			ManualHTTPRequestMode(api); 
			free(Fullurl);
			delete api;
			return(1);
		default:
			if (!csv) 
			{
				printf(" FHSCAN - HTTP vulnerability Scanner v1.4\n");
				printf("(c) Andres Tarasco - http://www.tarasco.org/security\n\n");
			}			
			api->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigMaxDownloadSize,"1024000"); /*Set the maximum download limit to 1Mb */
			break;
	}

	if ( ntargets < nthreads )  {
		nthreads = ntargets +1;
	}
	if (nthreads>MAXIMUM_WAIT_OBJECTS) {
		nthreads=MAXIMUM_WAIT_OBJECTS;
	}

#ifdef __WIN32__RELEASE__
	thread=(HANDLE*)malloc(sizeof(HANDLE)*nthreads);
	#else
	thread = (pthread_t*)malloc(sizeof(pthread_t)*nthreads);
#endif

	InitHTMLReport(ipfilepath,0,0,0,NULL,nthreads,1,FullUserList,1);

	dump = fopen("ScannerIPS.log","a+");

	if (!csv) ("Option  Server         status Port password      Path Description/banner\n");


	for(unsigned int i=0;i<nthreads;i++)
	{
#ifdef __WIN32__RELEASE__
		thread[i]=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE) ScanHosts, (LPVOID) api, 0, NULL);
		Sleep(50);
#else
		pthread_create(&thread[i], NULL, ScanHosts, (void *)api);
#endif
	}
#ifdef __WIN32__RELEASE__
	WaitForMultipleObjects(nthreads,thread,TRUE,INFINITE);
#else
	for(int i=0;i<nthreads;i++) pthread_join(thread[i], NULL);
#endif

#ifdef __WIN32__RELEASE__
	for(unsigned int i=0;i<nthreads;i++) {

		CloseHandle(thread[i]);
	}
#endif
	if (!csv)	{
		printf("scan Finished\t\t\t\t\t\n");fflush(stdout);
	} else fflush(stderr);

	CloseHTMLReport();


#ifdef __WIN32__RELEASE__
	free(thread);
#endif

	for(int i=0;i< nKnownRouters;i++) 
	{
		free(KnownRouters[i]);
	}
	free(KnownRouters);

	for(int i=0;i< nKnownWebservers;i++) {
		free(KnownWebservers[i]);
	}

	for(unsigned int i=0;i<ntargets;i++) 
	{
		if (targets[i].hostname) free(targets[i].hostname);

	}
	free(targets);
	targets=NULL;
	free(KnownWebservers);
	for(int i=0;i<nvlist;i++) 
	{
		free(vlist[i].Match);
	}

	free(logins);
	free(userpass);

	if (dump) 
	{
		fclose(dump);
	}
	delete api;
	return(1);

}






