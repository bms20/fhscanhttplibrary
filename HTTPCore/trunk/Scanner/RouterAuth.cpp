/*
*  Fast HTTP AUTH SCANNER
*
*  Router Auth Scanner Module: Scans for known authentication path
*
*/

#include "../HTTPCore/HTTP.h"
#include "../HTTPCore/HTTPResponse.h"
#include "estructuras.h"
#include "FHScan.h"
#include "Reporting/LogSettings.h"


extern int bruteforce;
#define MAX_TIMEOUT_RETRY 5 //Due to host timeout we will retry not more than 5 connections


HTTPSession* DuplicateData(HTTPSession* data)
{

	HTTPSession* new_data= new HTTPSession;
	new_data->ip=data->ip;
	_tcsncpy(new_data->hostname,data->hostname,sizeof(new_data->hostname)-1);
	new_data->port=data->port;
	new_data->NeedSSL=data->NeedSSL;

	new_data->request = new HTTPRequest;
	new_data->request->InitHTTPRequest((HTTPCHAR*)data->request->GetHeaders(),data->request->Data,data->request->DataSize);
	new_data->response = new HTTPResponse;
	new_data->response->InitHTTPResponse((HTTPCHAR*)data->response->GetHeaders(),data->response->Data,data->response->DataSize);

	new_data->url= _tcsdup(data->url);
	new_data->server=_tcsdup(data->server);
	new_data->status=data->status;
//	new_data->challenge=data->challenge;
	return(new_data);
}

/*******************************************************************************/
#define PASSWORD_NOT_FOUND -1
static int BruteforceAuth( HTTPAPI *api,HTTPHANDLE HTTPHandle,HTTPSession* data,struct _fakeauth *AuthData,int nUsers, USERLIST *userpass) {

	HTTPSession* new_response;
	int CookieNeeded=0;
    char *lpcookie=NULL;
    char cookie[256]="";
	int retries=MAX_TIMEOUT_RETRY;

	if (!bruteforce)
	{
		return(PASSWORD_NOT_FOUND);
    }

	if (_tcsstr(AuthData->postdata,_T("Cookie"))!=NULL)
	{
		CookieNeeded=1;
	}



    for(int k=0;k<nUsers;k++)
	{
#ifdef _DBG_
		printf("!!!Enviando login/password (%i/%i): %s - %s (authmethod %i )\n",k,nUsers,userpass[k].UserName,userpass[k].Password,challenge);
#endif

		do
		{
			if (!CookieNeeded)
			{
				//new_response3=api->SendHttpRequest( HTTPHandle,NULL,AuthData->method,AuthData->authurl,AuthData->postdata,(unsigned int)strlen(AuthData->postdata),userpass[k].UserName,userpass[k].Password,challenge);
				new_response=api->SendHttpRequest( HTTPHandle,NULL,AuthData->method,AuthData->authurl,AuthData->postdata,_tcslen(AuthData->postdata),userpass[k].UserName,userpass[k].Password);
			} else {
				api->SetHTTPConfig(HTTPHandle,ConfigCookie,AuthData->postdata);
				//new_response=api->SendHttpRequest( HTTPHandle,NULL,AuthData->method,AuthData->authurl,NULL,0,userpass[k].UserName,userpass[k].Password,challenge);
				new_response=api->SendHttpRequest( HTTPHandle,NULL,AuthData->method,AuthData->authurl,NULL,0,userpass[k].UserName,userpass[k].Password);
				api->SetHTTPConfig(HTTPHandle,ConfigCookie,(const char*)NULL);
			}

			if ( (new_response) &&(new_response->IsValidHTTPResponse()) ) break;
			delete new_response;
			new_response=NULL;
			retries--;
			Sleep(500);

		} while ( (!new_response) && (retries>0)  && (_tcslen(userpass[k].UserName)>0) && (_tcslen(userpass[k].Password)>0));


		/* Clean Cookie status */
		if (new_response)
		{
#ifdef _DBG_
			printf("ESTADO: %i\n",new_response->status);
#endif

			if (new_response->status <= HTTP_STATUS_REDIRECT ) //302
			{
				new_response->status=401;
				UpdateHTMLReport(new_response,MESSAGE_ROUTER_PASSFOUND,userpass[k].UserName,userpass[k].Password,new_response->url,NULL);
				delete new_response;
				return(k);
			}
			if (CookieNeeded==2)
			{
                lpcookie=data->response->GetHeaderValue(_T("Set-Cookie: "),0);
				if (lpcookie)
				{
                    snprintf(cookie,sizeof(cookie)-1,"Cookie: %s",lpcookie);
                }
			}
			delete new_response;
		}
	}
	return(PASSWORD_NOT_FOUND);
}
/*******************************************************************************/
HTTPSession* CheckRouterAuth(HTTPAPI *api,HTTPHANDLE HTTPHandle,HTTPSession* data,int nRouterAuth, struct _fakeauth *AuthData,int nUsers, USERLIST *userpass)
{
	HTTPSession* response;
	int ret;
	char *lpcookie=NULL;

/*
 * Revisamos si el dispositivo requiere autenticacion
 */



	for(int i=0;i<nRouterAuth;i++)
	{
		if ( (AuthData[i].status == data->status ) &&
		   ( (_tcsnccmp(data->server,AuthData[i].server,_tcslen(AuthData[i].server))==0) ||
			 (AuthData[i].server[0]=='*') ||
			 ( (_tcslen(data->server)==0) && (_tcscmp(AuthData[i].server,_T(" "))==0))
		   )
		   )
		{
			//printf("aki: %i\n",i);

#ifdef _DBG_
			printf("Verificando %i - %s\n",i,AuthData[i].authurl);
			printf("------------enviando---------------\n");
#endif
			if (i==0) {
				//printf("aki..........\n");
				response=DuplicateData(data);
				//printf("aki2\n");
			} else {
				int CookieNeeded=0;
				if (_tcsstr(AuthData[i].postdata,"Cookie")!=NULL)
				{
					CookieNeeded=1;

					if (_tcsstr(AuthData[i].postdata,_T("Cookie: !!!UPDATECOOKIE!!!"))!=NULL)
					{
						char tmp[256];
						lpcookie=data->response->GetHeaderValue(_T("Set-Cookie: "),0);
						if (lpcookie) {
							snprintf(tmp,sizeof(tmp)-1,"Cookie: %s",lpcookie);
							free(lpcookie);
							lpcookie=_tcsdup(tmp);
						} else CookieNeeded=0;
					} else{
						lpcookie=_tcsdup(AuthData[i].postdata);
					}
				}

				//  response=SendHttpRequest( data,AuthData[i].method,AuthData[i].authurl,AuthData[i].postdata,(char*)VERSION,NULL,NULL,NULL,NO_AUTH);
					if (CookieNeeded) {
						api->SetHTTPConfig(HTTPHandle,ConfigCookie,lpcookie);//AuthData[i].postdata);
						response=api->SendHttpRequest( HTTPHandle,NULL,AuthData[i].method,AuthData[i].authurl,NULL,0,NULL,NULL);
						api->SetHTTPConfig(HTTPHandle,ConfigCookie,(const char*)NULL);
						free(lpcookie);
					} else {
						response=api->SendHttpRequest( HTTPHandle,NULL,AuthData[i].method,AuthData[i].authurl,AuthData[i].postdata,_tcslen(AuthData[i].postdata),NULL,NULL);
					}
				}
				//SetHTTPConfig(HTTPHandle,OPT_HTTP_COOKIE,NULL);
			//

			if ( (response) && (!response->IsValidHTTPResponse()) )
			{
				delete response;
				response = NULL;
            }
		if (response)
		 {
#ifdef _DBG_
			 printf("code: %i buffer: %s\n",response->status,response->response->Data);
			 printf("/Headers: %s\n",response->response->Header);
			 //for(int j=0;j<response->nheaders;j++) printf("header: %s\n",response->header[j]);
#endif

			 if (response->status == HTTP_STATUS_DENIED) 
			 {
				 //ret=BruteforceAuth( HTTPHandle,data,&AuthData[i], nUsers, userpass,response->challenge);
				 ret=BruteforceAuth( api,HTTPHandle,response,&AuthData[i], nUsers, userpass);
				 if (ret!=PASSWORD_NOT_FOUND)
				 {
					 //UpdateHTMLReport(response,MESSAGE_ROUTER_PASSFOUND,userpass[ret].UserName,userpass[ret].Password,AuthData[i].authurl,NULL);

				 } else {
					 UpdateHTMLReport(response,MESSAGE_WEBFORMS_PASSNOTFOUND,_T("UNKNOWN"),_T("UNKNOWN"),AuthData[i].authurl,NULL);
				 }
				 return(response);
			 }
			 //response=(HTTPSession*)FreeRequest(response);
			 delete response;
			}
		}
	}
	return(NULL);
}

//---------------------------------------------------------------------------------

