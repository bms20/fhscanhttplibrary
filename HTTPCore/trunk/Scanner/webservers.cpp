//TODO: verificar codigo 302 como respuesta valida
//TODO: Verificar proxy_AUTH_REQUIRED para bruteforce :?
//TODO: definir vlist como VLIST *
//TODO: Migrar mensajes a un modulo externo.
//revisar porque se hacen varias peticiones al modulo 200 OK - GET /Fast-HTTP-Auth-Scanner-200-test/ HTTP/1.1

//SI la url principal "/" requiere auth 401 y todas las paginas requieren auth 401 revisar porque no se realiza autenticacion (por ejemplo NTLM)

#include "FHScan.h"
#include "../HTTPCore/HTTP.h"
#include "webservers.h"
#include "Reporting/LogSettings.h"

VLIST vlist[200]; //Vulnerability LIST
int nvlist = 0;

HTTPSession* DuplicateData(HTTPSession* data);
/******************************************************************************/
HTTPCHAR *Directories[50];
HTTPCHAR *Files[50];
HTTPCHAR *Extensions[10];
/******************************************************************************/
void BruteForceDirectory(HTTPAPI *api,HTTPHANDLE HTTPHandle, HTTPCHAR *base)
{
	unsigned int i, j;

	HTTPCHAR path[512];
	HTTPCHAR tmp[512];
	HTTPSession* response;

	i = 0;
	while (Directories[i][0])
	{
		_stprintf(path, _T("%s%s/"), base, Directories[i]);
		response = api->SendRawHTTPRequest(HTTPHandle, tmp, NULL,0);
		if (response)
		{
			if ( (response->IsValidHTTPResponse()) && (response->status == 200) )
			{
				_tprintf(_T("PATH Encontrado: %s\n"), path);
				BruteForceDirectory(api,HTTPHandle, base);
			}
			delete response;
		}
		i++;
	}

	i = 0;
	while (Files[i][0])
	{
		j = 0;
		while (Extensions[j++][0])
		{
			_stprintf(path, _T("%s/%s.%s"), base, Files[i], Extensions[j]);
			response = api->SendRawHTTPRequest (HTTPHandle, tmp, NULL,0);
			if (response) {
				if ( (response->IsValidHTTPResponse()) && (response->status == 200) )
				{
					_tprintf(_T("FILE Encontrado: %s\n"), path);
				}
				delete response;
			}
			j++;
		}
		i++;
	}

}
/******************************************************************************/
static BOOL CheckForWrongHTTPStatusCode(HTTPAPI *api,HTTPHANDLE HTTPHandle, unsigned int status)
{
	HTTPCHAR tmp[512];

	HTTPSession* new_response;
	_sntprintf(tmp, sizeof(tmp) - 1, _T("/FastHTTPAuthScanner%itest/"), status);
	new_response = api->SendHttpRequest(HTTPHandle, NULL,_T("GET"), tmp, NULL,0,NULL,NULL);
	if (new_response)
	{
		if (!new_response->IsValidHTTPResponse())
		{
			delete new_response;
			return (0);
		}
		if (new_response->status == status)
		{
			delete new_response;
			return (1);
		}
		delete new_response;
	}
	return (0);
}

/******************************************************************************/
int CheckVulnerabilities(HTTPAPI *api,HTTPHANDLE HTTPHandle, HTTPSession* data,int nUsers, USERLIST *userpass)
{

	HTTPSession* response;
	HTTPSession* bruteforce;
	unsigned int vulns = 0;
	HTTPCHAR tmp[512];
	int i, j, k;

	int Checked401 = 0, Ignore401 = 0;
	int Checked302 = 0, Ignore302 = 0;
	int Checked301 = 0, Ignore301 = 0;
	int Checked200 = 0, Ignore200 = 0;
	int PasswordLocated = 0;
	HTTPCHAR *lpUserName = NULL;
	HTTPCHAR *lpPassword = NULL;


	for (i = 0; i < nvlist; i++)
	{
		if ((_tcslen(vlist[i].server) == 0) || ((data->server != NULL) && (_tcsncicmp(data->server, vlist[i].server, _tcslen(vlist[i].server)) == 0)))
		{
			if (_tcscmp(vlist[i].url, data->url) == 0)
			{
				response = DuplicateData(data);
			} else
			{
				response = api->SendHttpRequest(HTTPHandle, NULL,_T("GET"),vlist[i].url, NULL,0,lpUserName, lpPassword);
			}
			if ((response) && (!response->IsValidHTTPResponse()) )
			{
				delete response;
				response = NULL;
			}
			if (response)
			{
				if ((response->status == HTTP_STATUS_DENIED) && (!Checked401)) {
					Checked401 = 1;
					Ignore401 = CheckForWrongHTTPStatusCode(api,HTTPHandle,HTTP_STATUS_DENIED);
				}
				if ((response->status == HTTP_STATUS_REDIRECT) && (!Checked302)) {
					Checked302 = 1;
					Ignore302 = CheckForWrongHTTPStatusCode(api,HTTPHandle,HTTP_STATUS_REDIRECT);
				}
				if ((response->status == HTTP_STATUS_MOVED) && (!Checked301))
				{
					Checked301 = 1;
					Ignore301 = CheckForWrongHTTPStatusCode(api,HTTPHandle,HTTP_STATUS_MOVED);
				}
				if ((response->status == HTTP_STATUS_OK) && (!Checked200))
				{
					Checked200 = 1;
					Ignore200 = CheckForWrongHTTPStatusCode(api,HTTPHandle,HTTP_STATUS_OK);
				}

				/* Posible bug */
				if ( (response->HasResponseData()) && (response->response->Datastrstr(_T("<h1>Index of"))))
				{
					UpdateHTMLReport(response,MESSAGE_WEBSERVER_VULNERABILITY,NULL,NULL,vlist[i].url, _T("(Directory Listing)"));
				}

				switch (response->status) {
				//code 5xx
				case HTTP_STATUS_SERVER_ERROR:
				case HTTP_STATUS_NOT_SUPPORTED:
				case HTTP_STATUS_BAD_GATEWAY:
				case HTTP_STATUS_SERVICE_UNAVAIL:
				case HTTP_STATUS_GATEWAY_TIMEOUT:
				case HTTP_STATUS_VERSION_NOT_SUP:
					//code 4xx
				case HTTP_STATUS_UNSUPPORTED_MEDIA:
				case HTTP_STATUS_URI_TOO_LONG:
				case HTTP_STATUS_REQUEST_TOO_LARGE:
				case HTTP_STATUS_PRECOND_FAILED:
				case HTTP_STATUS_LENGTH_REQUIRED:
				case HTTP_STATUS_GONE:
				case HTTP_STATUS_CONFLICT:
				case HTTP_STATUS_REQUEST_TIMEOUT:
				case HTTP_STATUS_PROXY_AUTH_REQ: //<-- MIRAR ESTO!!
				case HTTP_STATUS_NONE_ACCEPTABLE:
				case HTTP_STATUS_BAD_METHOD:
				case HTTP_STATUS_NOT_FOUND:
				case HTTP_STATUS_PAYMENT_REQ:
				case HTTP_STATUS_BAD_REQUEST:
					break;
				case HTTP_STATUS_FORBIDDEN:
					break;
				case HTTP_STATUS_DENIED:
					if (Ignore401) {
						//HACK - If the system require Authentication for all resources, we are going to test only the first one.
						if (Ignore401 > 1) {
							break;
						}
						Ignore401++;
					}
					vulns++;
					PasswordLocated = 0;

					for (k = 0; k < nUsers; k++)
					{
						//bruteforce = api->SendHttpRequest(HTTPHandle, NULL,"GET",vlist[i].url, NULL,0,userpass[k].UserName,userpass[k].Password, response->challenge); /* Buy a monitor with better resolution :p */
						bruteforce = api->SendHttpRequest(HTTPHandle, NULL,_T("GET"),vlist[i].url, NULL,0,userpass[k].UserName,userpass[k].Password); /* Buy a monitor with better resolution :p */
						if ((bruteforce) && (!bruteforce->IsValidHTTPResponse()))
						{
							delete bruteforce; bruteforce = NULL;
						}
						if (bruteforce)
						{
#ifdef _DBG_
							printf("STATUS: %i\n",bruteforce->status);
#endif
							if (bruteforce->status <= HTTP_STATUS_REDIRECT) //302
							{
								lpUserName=userpass[k].UserName;
								lpPassword = userpass[k].Password;
								vulns++;
								_sntprintf(tmp, sizeof(tmp) - 1, _T("%s %s"),vlist[i].vulnerability,_T("(Password Found)"));
								bruteforce->status=401;
								UpdateHTMLReport(bruteforce,MESSAGE_WEBSERVER_PASSFOUND,userpass[k].UserName,userpass[k].Password, vlist[i].url, tmp);//, "(Password Found)");
								delete bruteforce;
								bruteforce = NULL;
								PasswordLocated = 1;
								break;
							} else
							{
								delete bruteforce;
								bruteforce = NULL;
							}
						}
					}
					if (!PasswordLocated)
					{
						_sntprintf(tmp, sizeof(tmp) - 1, _T("%s %s"),vlist[i].vulnerability, _T("(Need Auth)"));
						UpdateHTMLReport(response,MESSAGE_WEBSERVER_PASSFOUND,_T(""), _T(""),vlist[i].url, tmp);
					}

					break;
				case HTTP_STATUS_REDIRECT: //<- Mirar si hay que validar previamente!!!
					if ((response->status == HTTP_STATUS_REDIRECT) && (Ignore302))
						break;
				case HTTP_STATUS_OK:
					if ((response->status == HTTP_STATUS_OK) && (Ignore200))
					{
						break;
                    }
				case HTTP_STATUS_CREATED:
				case HTTP_STATUS_ACCEPTED:
				case HTTP_STATUS_PARTIAL:
				case HTTP_STATUS_NO_CONTENT:
				case HTTP_STATUS_RESET_CONTENT:
				case HTTP_STATUS_PARTIAL_CONTENT:
				case HTTP_STATUS_AMBIGUOUS:
				case HTTP_STATUS_MOVED:
					if ((response->status == HTTP_STATUS_MOVED) && (Ignore301))
					{
						delete response;
						response = NULL;
						break;
					}

					if ((response->HasResponseData()) &&
					(response->response->Datastrstr(vlist[i].Ignoresignature) == NULL) &&
					(!response->response->Headerstrstr(vlist[i].Ignoresignature))  &&
					( (vlist[i].status == 0) || (response->status== vlist[i].status)))
					{
						if (vlist[i].nMatch == 0)
						{
							UpdateHTMLReport(response,MESSAGE_WEBSERVER_VULNERABILITY,NULL,NULL,vlist[i].url, vlist[i].vulnerability);
						} else
						{
							for (j = 0; j < vlist[i].nMatch; j++)
							{
#ifdef _FULLDBG_
								printf("verificando nmatch[%i]: %s\n",j,vlist[i].Match[j].description);
#endif
								if ( (_tcslen(vlist[i].Match[j].Ignorestring)== 0) ||
									((_tcslen(vlist[i].Match[j].Ignorestring)!= 0) &&
									(response->response->Datastrstr(vlist[i].Match[j].Ignorestring)== NULL)))
									{
									for (int k = 0; k< vlist[i].Match[j].nstrings; k++)
									{
#ifdef _FULLDBG_
										printf("verificando string[%i]: %s\n",k,vlist[i].Match[j].Validatestring[k]);
#endif
										if (response->response->Datastrstr(vlist[i].Match[j].Validatestring[k])!= NULL)
										{
											vulns++;
											_sntprintf(tmp,sizeof(tmp) - 1,_T("%s %s"),vlist[i].vulnerability,vlist[i].Match[j].description);
											UpdateHTMLReport(response,MESSAGE_WEBSERVER_VULNERABILITY,NULL,NULL,vlist[i].url, tmp);
											break;
										}
									}
								}
							}
						 }
					}

				default:
					break;
				}
				delete response;
				response = NULL;

			}
		}
	}

	return (vulns);
}

