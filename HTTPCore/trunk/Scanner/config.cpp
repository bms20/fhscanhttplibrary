#include "FHScan.h"
#include "estructuras.h"
#include "update.h"
#include "Input/InputHosts.h"

extern USERLIST        *userpass;
extern struct          _fakeauth FakeAuth[MAX_AUTH_LIST];
extern int              nUsers;
extern struct          _webform WEBFORMS[MAX_WEBFORMS];
extern int				nWebforms;
extern USERLOGIN	    *logins;
extern int				nLogins;
extern FILE*			ipfile;
extern int				bruteforce;
extern int				ShowAllhosts;
struct					_ports ports[MAX_PORTS];
int						nports=0;

extern int				nRouterAuth;
extern VLIST			vlist[200];
extern int				nvlist;
extern int				csv;
extern unsigned int		nthreads;
//extern unsigned long	currentip;
//extern unsigned long	endip;
extern int				FullUserList;
extern HTTPCHAR				**KnownWebservers;
extern int				nKnownWebservers;
extern HTTPCHAR				DirectoryLog[MAX_PATH+1];
extern HTTPCHAR				**KnownRouters;
extern int				nKnownRouters;
extern HTTPCHAR				*ipfilepath;

#ifdef XML_LIBRARY
HTTPCHAR *nmap=NULL;
#endif
HTTPCHAR *hosts=NULL;

extern HTTPCHAR *Fullurl;
extern HTTPCHAR *method;
extern HTTPCHAR *vhost;
extern HTTPCHAR *PostData;
extern int  PostDataSize ;
extern HTTPCHAR *additionalheaders;
extern int  spider;
extern int ShowLinks;
extern HTTPCHAR *LinkType;
extern int ShowResponse;
extern int proxyScanOnly;


#ifdef  __WIN32__RELEASE__
# if defined(_MSC_VER)
# else
#define _feof(a) ( (a->flags & _F_EOF) )
#define feof _feof
#endif
#endif

/******************************************************************************/
static void ValidateLine(HTTPCHAR *source,HTTPCHAR *dst) {
	int j=0;
	size_t len = _tcslen(source);
	for (unsigned int i=0;i<len;i++) {
		if (source[i]==_T('\\')) {
			switch (source[i+1]) {
		   case _T('r'):
			   source[i+1]=_T('\r');
			   break;
		   case _T('n'):
			   source[i+1]=_T('\n');
			   break;
		   case _T('t'):
			   source[i+1]=_T('\t');
			   break;
		   default:
			   dst[j]=source[i];
			   j++;
			   break;
			}
		} else {
			dst[j]=source[i];
			j++;
		}
	}
}
//------------------------------------------------------------------------------

int LoadKnownWebservers(HTTPCSTR path)
{
	HTTPCHAR tmp[100];
	int len=sizeof(tmp)/sizeof(HTTPCHAR);
	nKnownWebservers=0;
	FILE *webservers=_tfopen(path,_T("r"));
	if (!webservers) {
		return (0);
	}
	if (webservers)
	{
		while (!feof(webservers))
		{
			memset(tmp,'\0',sizeof(tmp));
			if (ReadAndSanitizeInput(webservers,tmp,len) && (_tcslen(tmp)>0) )
		 {
			 KnownWebservers=(HTTPCHAR**)realloc(KnownWebservers,sizeof(HTTPCHAR*)*(nKnownWebservers+1));
			 KnownWebservers[nKnownWebservers]=(HTTPCHAR*)malloc((len+1)*sizeof(HTTPCHAR));
			 _tcscpy(KnownWebservers[nKnownWebservers],tmp);
			 nKnownWebservers++;
		 }

		}
		fclose(webservers);
	}

	return(nKnownWebservers);
}


//------------------------------------------------------------------------------

int LoadKnownRouters(HTTPCSTR path)
{
	HTTPCHAR tmp[100];
	int len=sizeof(tmp)/sizeof(HTTPCHAR);
	FILE *webservers=_tfopen(path,_T("r"));
	if (!webservers) {
		return(0);
	}

	nKnownRouters=0;
	if (webservers)
	{
		while (!feof(webservers))
		{
			memset(tmp,'\0',sizeof(tmp));
			if (ReadAndSanitizeInput(webservers,tmp,len) && (_tcslen(tmp)>1))
		 {
			 KnownRouters=(HTTPCHAR**)realloc(KnownRouters,sizeof(HTTPCHAR*)*(nKnownRouters+1));
			 KnownRouters[nKnownRouters]=(HTTPCHAR *)malloc((len+1)*sizeof(HTTPCHAR));
			 _tcscpy(KnownRouters[nKnownRouters],tmp);

			 //            printf("%2.2i - %s\n",nKnownRouters,KnownRouters[nKnownRouters]);
			 nKnownRouters++;
			}    else {
				//                printf("Ignorando !%s!\n",tmp);
		 }

		}
		fclose(webservers);
	}
	return(nKnownRouters);
}


//------------------------------------------------------------------------------


int LoadWebForms(HTTPCSTR path)
{
	FILE *webforms=_tfopen(path,_T("r"));
	nWebforms=0;

	if (webforms) 
	{
		HTTPCHAR line[512];
		HTTPCHAR tmp[512];

		int i;
		for(i=0;i<MAX_WEBFORMS;i++) memset((HTTPCHAR*)&WEBFORMS[i],'\0',sizeof(struct _webform));
		while( (!feof(webforms)) && (nWebforms<MAX_WEBFORMS) )
		{
			//fgets(tmp,sizeof(tmp),webforms);

			//if ( (strlen(tmp)>6) && (tmp[0]!='#') && (tmp[0]!=';'))
			if (ReadAndSanitizeInput(webforms,tmp,sizeof(tmp)/sizeof(HTTPCHAR)))
			{
				memset(line,'\0',sizeof(line));
				ValidateLine(tmp,line);

				if (_tcsnccmp(line,_T("Model="),6)==0)
					_tcsncpy(WEBFORMS[nWebforms].model,line+6,sizeof(WEBFORMS[nWebforms].model)/sizeof(HTTPCHAR));

				if (_tcsnccmp(line,_T("status="),7)==0)
					WEBFORMS[nWebforms].status=_tstoi(line+7);
				if (_tcsnccmp(line,_T("server="),7)==0) {
					_tcsncpy(WEBFORMS[nWebforms].server,line+7,sizeof(WEBFORMS[nWebforms].server)/sizeof(HTTPCHAR));
				}
				if (_tcsnccmp(line,_T("Matchstring="),12)==0)
					_tcsncpy(WEBFORMS[nWebforms].matchstring,line+12,sizeof(WEBFORMS[nWebforms].matchstring)/sizeof(HTTPCHAR));
				if (_tcsnccmp(line,_T("ValidateImage="),14)==0)
					_tcsncpy(WEBFORMS[nWebforms].ValidateImage,line+14,sizeof(WEBFORMS[nWebforms].ValidateImage)/sizeof(HTTPCHAR));
				if (_tcsnccmp(line,_T("authurl="),8)==0)
					_tcsncpy(WEBFORMS[nWebforms].authurl,line+8,sizeof(WEBFORMS[nWebforms].authurl)/sizeof(HTTPCHAR));
				if (_tcsnccmp(line,_T("authmethod="),11)==0)
					_tcsncpy(WEBFORMS[nWebforms].authmethod,line+11,sizeof(WEBFORMS[nWebforms].authmethod)/sizeof(HTTPCHAR));
				if (_tcsnccmp(line,_T("requireloginandpass="),20)==0)
					WEBFORMS[nWebforms].requireloginandpass=_tstoi(line+20);
				if (_tcsnccmp(line,_T("authform="),9)==0)
					_tcsncpy(WEBFORMS[nWebforms].authform,line+9,sizeof(WEBFORMS[nWebforms].authform)/sizeof(HTTPCHAR));
				if (_tcsnccmp(line,_T("validauthstring="),16)==0) {
					_tcsncpy(WEBFORMS[nWebforms].validauthstring,line+16,sizeof(WEBFORMS[nWebforms].validauthstring)/sizeof(HTTPCHAR));
				}
				if (_tcsnccmp(line,_T("validauthstringalt="),19)==0) {
					_tcsncpy(WEBFORMS[nWebforms].validauthstringalt,line+19,sizeof(WEBFORMS[nWebforms].validauthstringalt)/sizeof(HTTPCHAR));
				}


				if (_tcsnccmp(line,_T("invalidauthstring="),18)==0) {
					_tcsncpy(WEBFORMS[nWebforms].invalidauthstring,line+18,sizeof(WEBFORMS[nWebforms].invalidauthstring)/sizeof(HTTPCHAR));
					nWebforms++;
				}
				//optional Headers
				if (_tcsnccmp(line,_T("invalidauthstringalt="),21)==0) {
					_tcsncpy(WEBFORMS[nWebforms-1].invalidauthstringalt,line+21,sizeof(WEBFORMS[nWebforms-1].invalidauthstringalt)/sizeof(HTTPCHAR));
				}
				if (_tcsnccmp(line,_T("AdditionalHeader="),17)==0) {
					_tcsncpy(WEBFORMS[nWebforms-1].AdditionalHeader,line+17,sizeof(WEBFORMS[nWebforms-1].AdditionalHeader)/sizeof(HTTPCHAR));
				}
				if (_tcsnccmp(line,_T("UpdateCookie="),13)==0)
					WEBFORMS[nWebforms-1].UpdateCookie=_tstoi(line+13);
				if (_tcsnccmp(line,_T("InitialCookieURL="),17)==0) {
					_tcsncpy(WEBFORMS[nWebforms-1].InitialCookieURL,line+17,sizeof(WEBFORMS[nWebforms-1].InitialCookieURL)/sizeof(HTTPCHAR));
				}
				if (_tcsnccmp(line,_T("ValidateAlternativeurl="),23)==0) {
					_tcsncpy(WEBFORMS[nWebforms-1].ValidateAlternativeurl,line+23,sizeof(WEBFORMS[nWebforms-1].ValidateAlternativeurl)/sizeof(HTTPCHAR));
				}
				if (_tcsnccmp(line,_T("LoadAdditionalUrl="),18)==0) {
					_tcsncpy(WEBFORMS[nWebforms-1].LoadAdditionalUrl,line+18,sizeof(WEBFORMS[nWebforms-1].LoadAdditionalUrl)/sizeof(HTTPCHAR));
				}
				if (_tcsnccmp(line,_T("ReconnectOnMatch="),17)==0) {
					_tcsncpy(WEBFORMS[nWebforms-1].ReconnectOnMatch,line+17,sizeof(WEBFORMS[nWebforms-1].ReconnectOnMatch)/sizeof(HTTPCHAR));
				}


			}
		}
		fclose(webforms);
	}
	return(nWebforms);
}

//------------------------------------------------------------------------------
int LoadUserList(HTTPCSTR path) {
	FILE *userlist;
	HTTPCHAR *p;
	HTTPCHAR user[200];

	nUsers=0;
	userlist=_tfopen(path,_T("r"));


	if (userlist)
	{

		while( (!feof(userlist)) )
		{
			memset(user,0,sizeof(user));
			_fgetts(user,sizeof(user)/sizeof(HTTPCHAR)-1,userlist);
			if ( (_tcslen(user)>1) && (user[0]!=_T('#')) )
			{
				p=user+_tcslen(user)-1;
				while ( (*p==_T('\r') ) || (*p==_T('\n')) || (*p==_T(' ')) ) { p[0]=_T('\0'); --p; }
				p=_tcschr(user,_T(':'));
				if (p)
				{
					if (!userpass) {
						userpass = (USERLIST *)malloc(sizeof(USERLIST));
					} else
						userpass=(USERLIST*)realloc(userpass,sizeof(USERLIST)*(nUsers+1));
					//memset(&userpass[nUsers],'\0',sizeof(USERLIST));
					p[0]=_T('\0');
					_tcsncpy(userpass[nUsers].UserName,user,sizeof(userpass[nUsers].UserName)/sizeof(HTTPCHAR)-1);
					_tcsncpy(userpass[nUsers].Password,p+1,sizeof(userpass[nUsers].Password)/sizeof(HTTPCHAR)-1);
					nUsers++;
				}
			}
		}
		fclose(userlist);
	}
	return(nUsers);
}

/******************************************************************************/
int LoadSingleUserList(HTTPCSTR path) {

	HTTPCHAR *p;
	HTTPCHAR user[200];
	int i=0;

	nLogins=0;



	FILE *userlist =_tfopen(path,_T("r"));
	if (userlist) {
		while( (!feof(userlist)) ) //&& (nLogins<MAX_USER_LIST) )
		{
			_fgetts(user,sizeof(user)/sizeof(HTTPCHAR)-1,userlist);
			if ( (_tcslen(user)>1) && (user[0]!=_T('#')) )
			{
				nLogins++;
			}
		} 
		fseek(userlist,0,SEEK_SET);
		logins=(USERLOGIN*)malloc(nLogins*sizeof(USERLOGIN));
		while( (!feof(userlist)) ) //&& (nLogins<MAX_USER_LIST) )
		{

			memset(user,'\0',sizeof(user));
			_fgetts(user,sizeof(user)/sizeof(HTTPCHAR)-1,userlist);
			if ( (_tcslen(user)>1) && (user[0]!=_T('#')) )
			{
				p=user+_tcslen(user)-1;
				while ( (*p==_T('\r') ) || (*p==_T('\n')) || (*p==_T(' ')) ) { p[0]=_T('\0'); --p; }
				memset(logins[i].user,0,40);
				_tcsncpy(logins[i].user,user,40-1);
				i++;
			}
		} 
		fclose(userlist);
	}

	return(nLogins);
}
/******************************************************************************/


int LoadWebservers(HTTPCSTR path) {

	FILE *webservers;
	HTTPCHAR tmp[512];
	HTTPCHAR line[512];



	webservers=_tfopen(path,_T("r"));
	if (!webservers) {
		return(0);
	}
	nvlist=-1;
	for(unsigned int i=0;i<sizeof(vlist)/sizeof(VLIST);i++) memset((HTTPCHAR *)&vlist[i],'\0',sizeof(VLIST));
	while (!feof(webservers))
	{
		memset(tmp,'\0',sizeof(tmp));
		if ( ReadAndSanitizeInput(webservers,tmp,sizeof(tmp)/sizeof(HTTPCHAR)) )
		{
			memset(line,'\0',sizeof(line));
			ValidateLine(tmp,line);

			if (_tcsnccmp(line,_T("vulnerability="),14)==0){
				nvlist++;
				_tcsncpy(vlist[nvlist].vulnerability,line+14,sizeof(vlist[nvlist].vulnerability)/sizeof(HTTPCHAR)-1);
			}
			if (_tcsnccmp(line,_T("status="),7)==0){
				vlist[nvlist].status=_tstoi(line+7);
			}
			if (_tcsnccmp(line,_T("server="),7)==0){
				_tcsncpy(vlist[nvlist].server,line+7,sizeof(vlist[nvlist].server)/sizeof(HTTPCHAR)-1);
			}
			if (_tcsnccmp(line,_T("url="),4)==0){
				_tcsncpy(vlist[nvlist].url,line+4,sizeof(vlist[nvlist].url)/sizeof(HTTPCHAR)-1);
			}
			if (_tcsnccmp(line,_T("Ignoresignature="),16)==0){
				_tcsncpy(vlist[nvlist].Ignoresignature,line+16,sizeof(vlist[nvlist].Ignoresignature)/sizeof(HTTPCHAR)-1);
			}
#define TOTALMATCHES vlist[nvlist].nMatch


			if (_tcsnccmp(line,_T("description="),12)==0){
				//RESERVAMOS MEMORIA PARA UN NUEVO MATCH
				vlist[nvlist].Match=(PMATCH)realloc(vlist[nvlist].Match,sizeof(MATCH)*(TOTALMATCHES+1));
				//PONEMOS A NULL LA VALIDACIoN
				//vlist[nvlist].Match[ TOTALMATCHES ].Validatestring=NULL;
				vlist[nvlist].Match[ TOTALMATCHES ].nstrings=0;
				//COPIAMOS LA DESCRIPCION
				_tcsncpy( vlist[nvlist].Match[vlist[nvlist].nMatch].description,line+12,sizeof(vlist[nvlist].Match[vlist[nvlist].nMatch].description)/sizeof(HTTPCHAR)-1);
				//INCREMENTAMOS EL CONTANDOR DE MATCHES
				vlist[nvlist].nMatch++;
			}

			if (_tcsnccmp(line,_T("Validatestring="),15)==0){
				//reservamos memoria para los matches..
				//vlist[nvlist].Match[ TOTALMATCHES -1].Validatestring=(char *)realloc(vlist[nvlist].Match[ TOTALMATCHES ].Validatestring, 200 * vlist[nvlist].Match[ TOTALMATCHES -1].nstrings+1);
				//copiamos la linea
				_tcsncpy(vlist[nvlist].Match[TOTALMATCHES -1].Validatestring[vlist[nvlist].Match[ TOTALMATCHES -1].nstrings],line+15,sizeof(vlist[nvlist].Match[TOTALMATCHES -1].Validatestring[vlist[nvlist].Match[ TOTALMATCHES -1].nstrings])/sizeof(HTTPCHAR)-1);
				vlist[nvlist].Match[ TOTALMATCHES  -1].nstrings++;
			}
			if (_tcsnccmp(line,_T("Ignorestring="),13)==0){
				//reservamos memoria para los matches..
				//vlist[nvlist].Match[ TOTALMATCHES -1].Validatestring=(char *)realloc(vlist[nvlist].Match[ TOTALMATCHES ].Validatestring, 200 * vlist[nvlist].Match[ TOTALMATCHES -1].nstrings+1);
				//copiamos la linea
				_tcscpy( vlist[nvlist].Match[TOTALMATCHES-1].Ignorestring-1,line+13);
			}


		}
	}
	nvlist++;
	fclose(webservers);
	return(nvlist);

}
//-----------------------------------------------------------------------------

int LoadRouterAuth(HTTPCSTR path) {
	FILE *RouterAuth;
	HTTPCHAR line[200];
	HTTPCHAR *p;
	//int nRouterAuth=0;
	nRouterAuth=0;

	RouterAuth=_tfopen(path,_T("r"));

	if (RouterAuth) {
		while (!feof(RouterAuth)) {
			_fgetts(line,sizeof(line)/sizeof(HTTPCHAR)-1,RouterAuth);
			if ( (_tcslen(line)>5) && line[0]!=_T('#') ) {
				p=line+_tcslen(line)-1;
				while ( (*p==_T('\r') ) || (*p==_T('\n')) || (*p==_T(' ')) ) { p[0]=_T('\0'); --p; }
				p=_tcstok(line,_T("|"));
				FakeAuth[nRouterAuth].status=_tstoi(p);
				p=_tcstok(NULL,_T("|"));
				_tcsncpy(FakeAuth[nRouterAuth].server,p,sizeof(FakeAuth[nRouterAuth].server)/sizeof(HTTPCHAR)-1);
				if ( (_tcslen(p)==1) && (p[0]==_T('*')) ) FakeAuth[nRouterAuth].server[0]=_T('\0');
				p=_tcstok(NULL,_T("|"));
				_tcsncpy(FakeAuth[nRouterAuth].authurl,p,sizeof(FakeAuth[nRouterAuth].authurl)/sizeof(HTTPCHAR)-1);
				p=_tcstok(NULL,_T("|"));
				_tcsncpy(FakeAuth[nRouterAuth].method,p,sizeof(FakeAuth[nRouterAuth].method)/sizeof(HTTPCHAR)-1);
				p=_tcstok(NULL,_T("|"));
				if (p) _tcsncpy(FakeAuth[nRouterAuth].postdata,p,sizeof(FakeAuth[nRouterAuth].postdata)/sizeof(HTTPCHAR)-1);
				nRouterAuth++;
			}
		}
		fclose(RouterAuth);
	}
	return(nRouterAuth);
}
/******************************************************************************/



void usage(void) {
#ifdef _UNICODE
	_tprintf(_T(" Fast HTTP vulnerability Scanner (FHScan) v1.5 (UNICODE Support)\n"));
#else
	_tprintf(_T(" Fast HTTP vulnerability Scanner (FHScan) v1.5\n"));	
#endif
	_tprintf(_T(" (c) Andres Tarasco - http://www.tarasco.org\n\n"));
#ifdef __WIN32__RELEASE__
	_tprintf(_T(" Usage: fhscan.exe  <parameters>\n\n"));
#else
	_tprintf(_T(" Usage: ./fhscan  <parameters>\n\n"));
#endif
	_tprintf(_T(" --hosts <ip1[-range][,hosts]>    ex: --hosts 192.168.1.1-255.255,www.google.com\n"));
	_tprintf(_T(" --threads <threads>              Number of threads.  default 10\n"));
	_tprintf(_T(" --ports <port>[,<port>,..]       example --p 80,81,82,8080 (default --ports 80)\n"));
	_tprintf(_T(" --sslports <sport>[,<sport>,,..] example -P 443,1443\n"));
	_tprintf(_T(" --logdir <directory>             Optional report log directory\n"));
	_tprintf(_T("\n **Advanced options:\n"));
	_tprintf(_T(" --ipfile  <ipfile>               Scan hosts from <ipfile>\n"));
#ifdef XML_LIBRARY
	_tprintf(_T(" --NmapFile <scan.xml>            scan hosts and ports from an nmap result file\n"));
#endif
	_tprintf(_T(" --fulluserlist                   Complete user list (slowest but more accurate)\n"));   
	_tprintf(_T(" --verbose                        Display verbose console information\n"));
	_tprintf(_T(" --nobruteforce                   Disable bruteforce (enabled by default)\n"));
	_tprintf(_T(" --proxyScanOnly                  Only searchs for HTTP proxy servers\n"));

	_tprintf(_T(" --csv                            CSV formated output\n"));
	_tprintf(_T(" --proxy http://host:port         Scan remote servers through HTTP proxy\n"));
	_tprintf(_T(" --proxyauth <user> <passwd>      Set username and password for the HTTP proxy\n"));
	_tprintf(_T("\n **Other options\n"));
	_tprintf(_T(" --update                         Download latest Fhscan release\n"));
	_tprintf(_T(" --EnableProxy                    Starts an HTTP Proxy instance at port 8080\n"));
	_tprintf(_T("\n **Manual request\n"));
	_tprintf(_T(" --request http[s]://host[:port][/url] Perform an HTTP request.\n"));
	_tprintf(_T(" --showlinks [link type]          Extract hyperlinks from requested url\n"));
	_tprintf(_T(" --showresponse                   Displays the remote HTTP response data\n"));
	_tprintf(_T(" --data <data>                    Post data to be submitted though HTTP\n"));
	_tprintf(_T(" --vhost <vhost>                  Alternate Host header\n"));
	_tprintf(_T(" --method <method>                Alternate HTTP method (GET by default)\n"));
	_tprintf(_T("\n"));

	_tprintf(_T(" **Example:\n"));
	_tprintf(_T(" fhscan --ports 80 --sslports 443,1433 --hosts 192.168.0.1-192.168.1.254 --threads 200\n\n"));
	return;

}
//-----------------------------------------------------------------------------



int LoadConfigurationFiles(HTTPAPI *api,int argc, HTTPCHAR *argv[]){
	int i;
	HTTPCHAR *p;
	int nhosts=0;
	HTTPCHAR dbg[512];



	if (argc<2) {
		usage();
		return(1);
	}
	for (i=1;i<argc;i++)
	{
		_tprintf(_T("Mirando: %s\n"),argv[i]);
		if ( argv[i][0]==_T('-'))
		{

			if (_tcscmp( argv[i],_T("--request"))==0)
			{
				Fullurl = _tcsdup(argv[i+1]);
				i++;
			} else
				if (_tcscmp( argv[i],_T("--showresponse"))==0)
				{
					ShowResponse=1;
				} else

					if (_tcscmp( argv[i],_T("--showlinks"))==0)
					{
						ShowLinks=1;
						if ( (argc>i+1) && (argv[i+1][0]!='-') ) {
							LinkType = _tcsdup(argv[i+1]);
							i++;
						}

					} else

						if (_tcscmp( argv[i],_T("--method"))==0)
						{
							method = _tcsdup(argv[i+1]);
							i++;
						} else
							if (_tcscmp( argv[i],_T("--data"))==0)
							{
								PostData = _tcsdup(argv[i+1]);
								PostDataSize = (int)_tcslen(PostData);
								i++;
							} else
								if (_tcscmp( argv[i],_T("--vhost"))==0)
								{
									vhost = _tcsdup(argv[i+1]);
									i++;
								} else
									if (_tcscmp( argv[i],_T("--proxyScanOnly"))==0)
									{
										proxyScanOnly = 1;
										bruteforce = 0;
									} else
										if (_tcscmp( argv[i],_T("--nobruteforce"))==0)
										{
											bruteforce=0;
										} else
											if (_tcscmp( argv[i],_T("--EnableProxy"))==0) {
												return(2);
											} else
												if (_tcscmp(argv[i],_T("--update"))==0) {
													UpdateFHScan(api); exit(1);
												} else
													if (_tcscmp( argv[i],_T("--fulluserlist"))==0) {
														FullUserList=1;
													} else
														if (_tcscmp( argv[i],_T("--verbose"))==0) {
															ShowAllhosts=1;
														} else
															if (_tcscmp( argv[i],_T("--logdir"))==0) {
																_tcscpy(DirectoryLog,argv[i+1]);
																i++;
															} else
																if (_tcscmp( argv[i],_T("--csv"))==0) {
																	csv = 1;
																} else
																	if ((_tcscmp( argv[i],_T("--ports"))==0) || (_tcscmp( argv[i],_T("--port"))==0) ) {
																		p=_tcstok(argv[i+1],_T(","));
																		while (p!=NULL) {
																			ports[nports].port=_tstoi(p);
																			ports[nports].ssl=0;
																			p=_tcstok(NULL,_T(","));
																			nports++;
																		}
																		i++;
																	} else

																		if ( (_tcscmp( argv[i],_T("--sslports"))==0) || (_tcscmp( argv[i],_T("--sslport"))==0) ){
																			p=_tcstok(argv[i+1],_T(","));
																			while (p!=NULL) {
																				ports[nports].port=_tstoi(p);
																				ports[nports].ssl=1;
																				p=_tcstok(NULL,_T(","));
																				nports++;
																			}
																			i++;
																		} else


																			if (_tcscmp( argv[i],_T("--threads"))==0) {
																				nthreads=_tstoi(argv[i+1]);
																				i++;
																			} else
																				if (_tcscmp( argv[i],_T("--proxy"))==0)
																				{
																					_tprintf(_T("estableciendo proxy...\n"));
																					HTTPCHAR proxyhost[512];
																					HTTPCHAR proxyport[10];
																					if ( _stscanf( argv[i+1], _T("http://%[^:/]:%s"), proxyhost, proxyport ) == 2 )
																					{
																						api->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigProxyHost,proxyhost);
																						api->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigProxyPort,proxyport);
																					}  else {
																						_tprintf(_T(" [-] Invalid proxy parameter %s\n"),argv[i+1]);
																						_tprintf(_T(" [-] Should be http://host:port\n"));
																						return(1);
																					}

																					i++;
																				} else
																					if (_tcscmp( argv[i],_T("--proxyauth"))==0) {
																						api->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigProxyUser,argv[i+1]);
																						api->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigProxyPass,argv[i+2]);
																						i+=2;
																					} else

																						if (_tcscmp( argv[i],_T("--ipfile"))==0) 
																						{
																							ipfilepath=argv[i+1];
																							ipfile=_tfopen(ipfilepath,_T("r"));
																							if (ipfile) {
																								_tprintf(_T("[+] Loaded ips from %s\n"),argv[i+1]);
																							} else {
																								_tprintf(_T("[-] Unable to load ips from %s\n"),argv[i+1]);
																								usage();
																								return(1);
																							}
																							i++;
																						} else
#ifdef XML_LIBRARY
																							if ( (_tcscmp( argv[i],_T("--NmapFile"))==0) || (_tcscmp( argv[i],_T("--nmapfile"))==0) )
																							{
																								nmap = argv[i+1];
																								i++;
																							} else 
#endif
																								if ( (_tcscmp( argv[i],_T("--hosts"))==0) || (_tcscmp( argv[i],_T("--host"))==0) )
																								{
																									hosts= argv[i+1];																	
																									i++;
																								} else {
																									usage();
																									_tprintf(_T("Invalid parameter %s\n"),argv[i]);
																									return(1);
																								}
		}
	}

	//manual requests
	if (Fullurl) {
		return(3);
	}


	if (FullUserList) {
		i=LoadUserList(_T("UserListMulti.ini"));
	} else {
		i=LoadUserList(_T("UserListMulti-simple.ini"));
	}
	if (!i) {
		if (!csv) _tprintf(_T("[-] UserList file not found\n"));
		return(1);
	} else {
		if (!csv) _tprintf(_T("[+] Loaded %i user/pass combinations\n"),i);
	}

	nRouterAuth=LoadRouterAuth(_T("RouterAuth.ini"));
	if (!nRouterAuth) {
		if (!csv) _tprintf(_T("[-] Unable to load Router Auth engine\n"));
		return(1);
	} else {
		if (!csv) _tprintf(_T("[+] Loaded %i Router authentication schemes\n"),nRouterAuth);
	}
	i=LoadWebForms(_T("webforms.ini"));
	if (!i) {
		if (!csv) _tprintf(_T("[-] Unable to load Webforms auth engine\n"));
		return(1);
	} else {
		if (!csv) _tprintf(_T("[+] Loaded %i webform authentication schemes\n"),i);
	}
	i=LoadSingleUserList(_T("UserListSingle.ini"));
	if (!i) {
		if (!csv) _tprintf(_T("[-] Unable to load Single login file\n"));
		return(1);
	} else {
		if (!csv) _tprintf(_T("[+] Loaded %i Single Users\n"),i);
	}

	i=LoadWebservers(_T("Webservers.ini"));
	if (!i) {
		if (!csv) _tprintf(_T("[-] Unable to load vulnerability database\n"));
		return(1);
	} else {
		if (!csv) _tprintf(_T("[+] Loaded %i vulnerabilities\n"),i);
	}

	i=LoadKnownWebservers(_T("KnownWebservers.ini"));
	if (!i) {
		if (!csv) _tprintf(_T("[-] Unable to load Known Webservers database\n"));
		return(1);
	} else {
		if (!csv) _tprintf(_T("[+] Loaded %i Known Webservers\n"),i);
	}

	i=LoadKnownRouters(_T("KnownRouters.ini"));
	if (!i) {
		if (!csv) _tprintf(_T("[-] Unable to load Known Routers database\n"));
		return(1);
	} else {
		if (!csv) _tprintf(_T("[+] Loaded %i Known Routers\n"),i);
	}

	if (nports==0) {
		nports=1;
		ports[0].port=80;
		ports[0].ssl=0;
	}

#ifdef XML_LIBRARY
	if (nmap) ParseNmapXMLFile(nmap);
#endif
	if (hosts) nhosts = ParseHosts(hosts);
	if (ipfile) nhosts += Parseipfile(ipfile);




	if (( (nhosts==0) && (ipfile==NULL)
#ifdef XML_LIBRARY
		&& (!nmap)
#endif
		)  ) usage();

	if (!csv)
	{
		if (ipfile) {
			_tprintf(_T("[+] Scanning hosts from ip file\n"),nhosts);
		} else {
			/*
			char tmp[20];
			snprintf(tmp,sizeof(tmp)-1,"%s)\n",inet_ntoa(ip2.sin_addr));
			snprintf(dbg,sizeof(dbg)-1,"[+] Scanning %i hosts  (%s  - %s",nhosts,inet_ntoa(ip1.sin_addr),tmp);
			printf("%s",dbg);
			*/
		}

		_tprintf(_T("[+] Scanning %i ports - bruteforce is %s\n\n"),nports,bruteforce ? _T("active") : _T("Inactive"));
	}

	return(0);
}



