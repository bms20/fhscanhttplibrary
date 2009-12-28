#include "FHScan.h"
#include "Input/InputHosts.h"
#include "config.h"

typedef struct update{
	int Mayor;
	int Minor;
	int Build;
	int signature;

	HTTPCHAR host[256];
	int port;
	int ssl;
	HTTPCHAR version_url[256];
	HTTPCHAR package_url[256];
	HTTPCHAR signature_url[256];
	HTTPCHAR *news;
	HTTPCHAR linux_url[256];
} UPDATE;

int CheckConfigFile(HTTPCSTR filename,UPDATE *local)
{
	FILE *update=_tfopen(filename,"r");
	HTTPCHAR line[1024];
	if (!update)
	{
		return(0);
	}
	while (!feof(update))
	{
			if ( ReadAndSanitizeInput(update,line,sizeof(line)) ){
				if (memcmp(line,"FHSCAN_MAYOR_VERSION= ",21)==0)
				{
					local->Mayor=_tstoi(line+21+1);
				}
				if (memcmp(line,"FHSCAN_MINOR_VERSION= ",21)==0)
				{
					local->Minor=_tstoi(line+21+1);
				}
				if (memcmp(line,"FHSCAN_BUILD_VERSION= ",21)==0)
				{
					local->Build=_tstoi(line+21+1);
				}
				if (memcmp(line,"FHSCAN_SIGNATUREFILE= ",21)==0)
				{
					local->signature=_tstoi(line+21+1);
				}
	//----
				if (memcmp(line,"FHSCAN_UPDATE_SERVER= ",21)==0)
				{
					_tcscpy(local->host,line+21+1);
				}
				if (memcmp(line,"FHSCAN_UPDATE_PORT__= ",21)==0)
				{
					local->port=_tstoi(line+21+1);
				}
				if (memcmp(line,"FHSCAN_PROTOCOL_PORT= ",21)==0)
				{
					local->ssl=_tstoi(line+21+1);
				}
				if (memcmp(line,"FHSCAN_CHECK_VERSION= ",21)==0)
				{
					_tcscpy(local->version_url,line+21+1);
				}
				if (memcmp(line,"FHSCAN_DWNLD_PACKAGE= ",21)==0)
				{
					_tcscpy(local->package_url,line+21+1);
				}
				if (memcmp(line,"FHSCAN_SIGNATUREFILE= ",21)==0)
				{
					_tcscpy(local->signature_url,line+21+1);
				}
				if (memcmp(line,"FSCAN_DOWNLOAD_LINUX= ",21)==0)
				{
					_tcscpy(local->linux_url,line+21+1);
				}

				if (memcmp(line,"FSCAN_UPDATE_NEWS___= ",21)==0)
				{
					local->news=_tcsdup(line+21+1);
				}

			}

	}

	fclose(update);
	return(1);

}
int UpdateFHScan(HTTPAPI *api)
{
	FILE *update;
//	HTTPCHAR buf[4096];
	HTTPCHAR tmp[256];

	HTTPHANDLE HTTPHandle;
	HTTPHANDLE NEWHTTPHandle;

	HTTPSession* DATA;
	HTTPSession* DOWNLOAD;
	UPDATE local,remote;
//	HTTPCHAR *p;
	int ret;
	int completeupdate=0;


	ret=CheckConfigFile("FHSCAN_release.dat",&local);
	if (!ret)
	{
		printf("[-] Unable to locate FHSCAN_release.dat. Please manually check for updates at http://www.tarasco.org\n");
		return(1);
	}
	
	printf("[+] Installed FHScan Build: %i.%i.%i\n",local.Mayor,local.Minor,local.Build);

	//InitHTTPApi();
	printf("[+] Connecting with: %s:%i SSL: %i\n",local.host,local.port,local.ssl);
	HTTPHandle=api->InitHTTPConnectionHandle(local.host,local.port,local.ssl);
	if (HTTPHandle == INVALID_HHTPHANDLE_VALUE)
	{
		printf("[-] Unable to resolve %s\n",local.host);
		return(1);
	}

	DATA=api->SendHttpRequest(HTTPHandle,NULL,"GET",local.version_url,NULL,0,NULL,NULL);
	if ((!DATA) || (!DATA->response) )
	{
		printf("[-] Request error\n");
		return(1);
	}
	if ( (DATA->status!=200) || (DATA->response->DataSize==0) )
	{
		printf("[-] Unable to locate http%s://%s%s:%i \n",local.ssl ? "s": "", local.host,local.version_url,local.port);
		return(1);
	}
	update=_tfopen("tmp.dat","w");
	fwrite(DATA->response->Data,1,DATA->response	->DataSize,update);
	fclose(update);

	ret=CheckConfigFile("tmp.dat",&remote);

	if ( (remote.Mayor >local.Mayor) ||
		 ( (remote.Mayor == local.Mayor) && (remote.Minor > local.Minor) ) ||
		 ( (remote.Mayor == local.Mayor) && (remote.Minor == local.Minor) && (remote.Build >local.Build)) )
	{
		printf("[+] Current FHScan Build: %i.%i.%i\n",remote.Mayor,remote.Minor,remote.Build);
		printf("[+] Downloading http%s://%s%s:%i \n",remote.ssl ? "s": "", remote.host,remote.package_url,remote.port);
		if (remote.news) {
			printf("[+] News: %s\n",remote.news);
		}
		NEWHTTPHandle=api->InitHTTPConnectionHandle(remote.host,remote.port,remote.ssl);
#ifdef __WIN32__RELEASE__
		DOWNLOAD=api->SendHttpRequest(NEWHTTPHandle,NULL,_T("GET"),remote.package_url,NULL,0,NULL,NULL);
#else
		DOWNLOAD=api->SendHttpRequest(NEWHTTPHandle,NULL,_T("GET"),remote.linux_url,NULL,0,NULL,NULL);
#endif
		if ( (DOWNLOAD) && (DOWNLOAD->response) && (DOWNLOAD->response->DataSize) )
		{
#ifdef __WIN32__RELEASE__
			sprintf(tmp,"FHScan_%i.%i.%i.zip",remote.Mayor,remote.Minor,remote.Build);
#else
			sprintf(tmp,"FHScan-%i.%i.%i-i386-Backtrack3.tgz",remote.Mayor,remote.Minor,remote.Build);
#endif
			printf("[+] Saving file as: %s  (please extract it manually)\n",tmp);
			update=_tfopen(tmp,_T("wb"));
			fwrite(DOWNLOAD->response->Data,1,DOWNLOAD->response->DataSize,update);
			fclose(update);
			printf("[+] Saving FHSCAN_release.dat\n");
			update=_tfopen("FHSCAN_release.dat","w");
			fwrite(DATA->response->Data,1,DATA->response->DataSize,update);
			fclose(update);
			//FreeRequest(DATA);
            delete DATA;
			//FreeRequest(DOWNLOAD);
			delete DOWNLOAD;
			api->EndHTTPConnectionHandle(HTTPHandle);
			api->EndHTTPConnectionHandle(NEWHTTPHandle);
//			CloseHTTPApi();
			completeupdate=1;
			delete api;
		} else {
			printf("[-] Unable to download FHScan file\n");
		}
		return(0);

	}

	if ( ( remote.signature > local.signature ) && (!completeupdate) )
	{
		printf("[+] Current FHScan Build: %i.%i.%i Signature: %i\n",remote.Mayor,remote.Minor,remote.Build,remote.signature);
		printf("[+] Downloading http%s://%s%s:%i \n",remote.ssl ? "s": "", remote.host,remote.signature_url,remote.port);
		NEWHTTPHandle=api->InitHTTPConnectionHandle(remote.host,remote.port,remote.ssl);
		DOWNLOAD=api->SendHttpRequest(NEWHTTPHandle,NULL,"GET",remote.signature_url,NULL,0,NULL,NULL);
		if ( (DOWNLOAD) && (DOWNLOAD->response) && (DOWNLOAD->response->DataSize) && (DOWNLOAD->status==200) )
		{
			sprintf(tmp,"FHScan_signature_%i.%i.%i_%i.zip",remote.Mayor,remote.Minor,remote.Build,remote.signature);
			printf("[+] Saving file as: %s (please extract it manually)\n",tmp);
			update=_tfopen(tmp,"w");
			fwrite(DOWNLOAD->response->Data,1,DOWNLOAD->response->DataSize,update);
			fclose(update);
			printf("[+] Saving FHSCAN_release.dat\n");
			update=_tfopen("FHSCAN_release.dat","w");
			fwrite(DATA->response->Data,1,DATA->response->DataSize,update);
			fclose(update);
			delete DATA;
			delete DOWNLOAD;
//			FreeRequest(DATA);
//			FreeRequest(DOWNLOAD);

			api->EndHTTPConnectionHandle(HTTPHandle);
			api->EndHTTPConnectionHandle(NEWHTTPHandle);
//			CloseHTTPApi();
			delete api;

		} else {
			printf("[-] Unable to download FHScan siagnature file\n");
		}
		return(0);

	}

	printf("[+] FHScan is up to date. Enjoy =) \n");
	delete(DATA);
	api->EndHTTPConnectionHandle(HTTPHandle);


	delete api;
   //	CloseHTTPApi();
	return(0);


}
