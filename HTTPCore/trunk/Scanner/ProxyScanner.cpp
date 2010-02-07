#include "FHScan.h"
#include "Reporting/LogSettings.h"

const HTTPCHAR HTTPAKAMAIPROXYGET[]= _T("GET http://www.fbi.gov/ HTTP/1.1\r\nHost: www.fbi.gov\r\n\r\n");
#define HTTPPROXYTESTHOST  _T("www.fbi.gov")
#define HTTPPROXYTESTPORT  80
#define HTTPPROXYTESTURL _T("/")
#define HTTPPROXYTESTMATCH  _T("Federal Bureau of Investigation Homepage")

//Include GeoLocalization API: http://ipinfodb.com/ip_query_country.php?ip=xx.xx.xx.xx
//http://ipinfodb.com/ip_query.php?ip=xxx.xxx.xxx.xxx

//Additional ip location tests: http://www.ip2location.com/1.2.3.4
//http://www.ip2location.com/ib1/
Threading test;


int ProxyTest(HTTPAPI *api,HTTPHANDLE HTTPHandle)
{
	FILE *proxy = NULL;
	HTTPCHAR tmp[512];
	HTTPSession* response;
	int ret=0;

	HTTPCHAR *ProxyConfig = api->GetHTTPConfig (GLOBAL_HTTP_CONFIG,ConfigProxyHost);
	if (!ProxyConfig)
	{
		_stprintf(tmp,_T("GET http://%s:%i%s HTTP/1.1\r\nHost: %s\r\n\r\n"),HTTPPROXYTESTHOST,HTTPPROXYTESTPORT,HTTPPROXYTESTURL,HTTPPROXYTESTHOST);

		response = api->SendRawHTTPRequest(HTTPHandle,HTTPAKAMAIPROXYGET, NULL,0);
		if (response)
		{
			if (!response->response->DataSize) {
				delete response;
			} else
			{
				if (response->response->Datastrstr(HTTPPROXYTESTMATCH) != NULL)
				{
					ret=1;
				} else {
					if (response->status==502)
					{
						ret=2;
					} else if (response->status==407) 
					{
						ret = 6;

					} else {
						delete response;

					}
				}
			}

		}
		if (!ret)
		{
			_stprintf(tmp,_T("CONNECT %s:%i HTTP/1.0\r\n\r\n"),HTTPPROXYTESTHOST,HTTPPROXYTESTPORT);
			response = api->SendRawHTTPRequest(HTTPHandle, tmp,NULL,0);
			if (response)
			{
				if (response->status==200)
				{
					//FreeRequest(response);
					delete response;
					response = api->SendHttpRequest(HTTPHandle,HTTPPROXYTESTHOST,_T("GET"),HTTPPROXYTESTURL,NULL,0,NULL,NULL);
					if (response)
					{
						if ( (response->response->Data) && (response->response->Datastrstr(HTTPPROXYTESTMATCH) != NULL) )
						{
							ret=3;
						} else {
							//FreeRequest(response);
							delete response;
							/* TODO: DEsconectar la conexion aqui, puesto que si se trata de un proxy correcto podemos estar enviando la peticion realmente al $HOST :/*/
							response = api->SendRawHTTPRequest(HTTPHandle, _T("CONNECT FHSCAN.nonexistent.asdfg:443 HTTP/1.0\r\n\r\n"),NULL,0);
							if (response){
								if (response->status==502){
									ret=4;
								} else {
									//FreeRequest(response);
									delete response;
									response = api->SendRawHTTPRequest(HTTPHandle, _T("GET http://127.0.0.1:22/ HTTP/1.0\r\n\r\n"),NULL,0);
									if (response)
									{
										if ( (response->response->Data) && (response->response->Datastrstr(_T("OpenSSH"))!=NULL) ) {
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
				api->CancelHTTPRequest(HTTPHandle);
			}
		}


		if (ret){
			test.LockMutex();
			proxy = _tfopen(_T("ProxyList.txt"), _T("a+"));
			_stprintf(tmp,_T("%s:%s\r\n"),api->GetHTTPConfig(HTTPHandle,ConfigHTTPHost),api->GetHTTPConfig(HTTPHandle,ConfigHTTPPort));
			fwrite(tmp, 1, _tcslen(tmp), proxy);
			fclose(proxy);
			test.UnLockMutex();
		}
		switch (ret){
			case 1:
				_tcscpy(response->url, _T("/"));
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						_T("The remote Webserver is acting as an HTTP Proxy Server. A GET request against www.fbi.gov was forwarded."));
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */
			case 2:
				_tcscpy(response->url, _T("/"));
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						_T("The remote Webserver is acting as an HTTP Proxy Server. However the request against www.fbi.gov failed."));
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */
			case 3:
				_tcscpy(response->url, _T("/"));
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						_T("The remote Webserver is acting as an HTTP Proxy Server. A CONNECT + GET request against www.fbi.gov was forwarded."));
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */
			case 4:
				_tcscpy(response->url, _T("/"));
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						_T("The remote Webserver is acting as an HTTP Proxy Server. However the CONNECT method against www.fbi.gov:80 failed (maybe only port 443 is accepted)."));
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */
			case 5:
				_tcscpy(response->url, _T("/"));
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						_T("The remote Webserver is acting as an HTTP Proxy Server. The request \"GET http://127.0.0.1:22/ HTTP/1.0\" returned the SSH version."));
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */
			case 6:
				_tcscpy(response->url, _T("/"));
				UpdateHTMLReport(
						response,
						MESSAGE_WEBSERVER_VULNERABILITY,NULL,
						NULL,response->url,
						_T("The remote Webserver is acting as an HTTP Proxy Server. Authentication required."));
				//FreeRequest(response);
				delete response;
				return(1); /* Its an HTTP Proxy - Do not perform additional tests */

			default:
				break;
		}
	}
	return(1);
}
