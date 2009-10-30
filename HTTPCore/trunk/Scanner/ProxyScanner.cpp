#include "FHScan.h"
#include "Reporting/LogSettings.h"

const char HTTPAKAMAIPROXYGET[]= "GET http://www.fbi.gov/ HTTP/1.1\r\nHost: www.fbi.gov\r\n\r\n";
#define HTTPPROXYTESTHOST  "www.fbi.gov"
#define HTTPPROXYTESTPORT  80
#define HTTPPROXYTESTURL "/"
#define HTTPPROXYTESTMATCH  "Federal Bureau of Investigation Homepage"

//Include GeoLocalization API: http://ipinfodb.com/ip_query_country.php?ip=xx.xx.xx.xx
//http://ipinfodb.com/ip_query.php?ip=xxx.xxx.xxx.xxx

//Additional ip location tests: http://www.ip2location.com/1.2.3.4
//http://www.ip2location.com/ib1/
Threading test;


int ProxyTest(HTTPAPI *api,HTTPHANDLE HTTPHandle)
{
	FILE *proxy = NULL;
	char tmp[512];
	PREQUEST response;
	int ret=0;

	char *ProxyConfig = api->GetHTTPConfig (GLOBAL_HTTP_CONFIG,ConfigProxyHost);
	if (!ProxyConfig)
	{

		sprintf(tmp,"GET http://%s:%i%s HTTP/1.1\r\nHost: %s\r\n\r\n",HTTPPROXYTESTHOST,HTTPPROXYTESTPORT,HTTPPROXYTESTURL,HTTPPROXYTESTHOST);

		response = api->SendRawHTTPRequest(HTTPHandle,HTTPAKAMAIPROXYGET,(unsigned int)strlen(HTTPAKAMAIPROXYGET), NULL,0);
		if (response)
		{
			if (!response->response->DataSize) {
				delete response;
			} else
			{
				if (strstr(response->response->Data,HTTPPROXYTESTMATCH) != NULL)
				{
					ret=1;
				} else {
					if (response->status==502)
					{
						ret=2;
					} else {
						delete response;

					}
				}
			}

		}
		if (!ret)
		{
			sprintf(tmp,"CONNECT %s:%i HTTP/1.0\r\n\r\n",HTTPPROXYTESTHOST,HTTPPROXYTESTPORT);
			response = api->SendRawHTTPRequest(HTTPHandle, tmp,(unsigned int)strlen(tmp),NULL,0);
			if (response)
			{
				if (response->status==200)
				{
					//FreeRequest(response);
					delete response;
					response = api->SendHttpRequest(HTTPHandle,HTTPPROXYTESTHOST,"GET",HTTPPROXYTESTURL,NULL,0,NULL,NULL);
					if (response)
					{
						if ( (response->response->Data) && (strstr(response->response->Data,HTTPPROXYTESTMATCH) != NULL) )
						{
							ret=3;
						} else {
							//FreeRequest(response);
							delete response;
							/* TODO: DEsconectar la conexion aqui, puesto que si se trata de un proxy correcto podemos estar enviando la peticion realmente al $HOST :/*/
							response = api->SendRawHTTPRequest(HTTPHandle, "CONNECT FHSCAN.nonexistent.asdfg:443 HTTP/1.0\r\n\r\n",49,NULL,0);
							if (response){
								if (response->status==502){
									ret=4;
								} else {
									//FreeRequest(response);
									delete response;
									response = api->SendRawHTTPRequest(HTTPHandle, "GET http://127.0.0.1:22/ HTTP/1.0\r\n\r\n",37,NULL,0);
									if (response)
									{
										if ( (response->response->Data) && (strstr(response->response->Data,"OpenSSH")!=NULL) ) {
											ret=5;
										} else {
											//FreeRequest(response);
											delete response;
										}

									}
								}
							}
						}
					}
				} else {
					//FreeRequest(response);
					delete response;
				}
				//We must close the connection
				api->CancelHttpRequest(HTTPHandle,HTTP_REQUEST_CURRENT);
			}
		}


		if (ret){
			test.LockMutex();
			proxy = fopen("ProxyList.txt", "a+");
			sprintf(tmp,"%s:%s\r\n",api->GetHTTPConfig(HTTPHandle,ConfigHTTPHost),api->GetHTTPConfig(HTTPHandle,ConfigHTTPPort));
			fwrite(tmp, 1, strlen(tmp), proxy);
			fclose(proxy);
			test.UnLockMutex();
		}
		switch (ret){
			case 1:
				strcpy(response->url, "/");
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						"The remote Webserver is acting as an HTTP Proxy Server. A GET request against www.fbi.gov was forwarded.");
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */
			case 2:
				strcpy(response->url, "/");
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						"The remote Webserver is acting as an HTTP Proxy Server. However the request against www.fbi.gov failed.");
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */
			case 3:
				strcpy(response->url, "/");
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						"The remote Webserver is acting as an HTTP Proxy Server. A CONNECT + GET request against www.fbi.gov was forwarded.");
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */
			case 4:
				strcpy(response->url, "/");
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						"The remote Webserver is acting as an HTTP Proxy Server. However the CONNECT method against www.fbi.gov:80 failed (maybe only port 443 is accepted).");
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */
			case 5:
				strcpy(response->url, "/");
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						"The remote Webserver is acting as an HTTP Proxy Server. The request \"GET http://127.0.0.1:22/ HTTP/1.0\" returned the SSH version.");
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */
			default:
				break;
		}
	}
	return(1);
}