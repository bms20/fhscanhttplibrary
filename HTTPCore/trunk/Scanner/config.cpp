
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
extern unsigned long	currentip;
extern unsigned long	endip;
extern int				FullUserList;
extern char				**KnownWebservers;
extern int				nKnownWebservers;
extern char				DirectoryLog[MAX_PATH+1];
extern char				**KnownRouters;
extern int				nKnownRouters;
extern char				*ipfilepath;

#ifdef XML_LIBRARY
char *nmap=NULL;
#endif
char *hosts=NULL;

extern char *Fullurl;
extern char *method;
extern char *vhost;
extern char *PostData;
extern int  PostDataSize ;
extern char *additionalheaders;
extern int  spider;
extern int ShowLinks;
extern char *LinkType;
extern int ShowResponse;
extern int proxyScanOnly;





/******************************************************************************/
static void ValidateLine(char *source,char *dst) {
	int j=0;
	unsigned int len = ( unsigned int )strlen(source);
	for (unsigned int i=0;i<len;i++) {
		if (source[i]=='\\') {
			switch (source[i+1]) {
		   case 'r':
			   source[i+1]='\r';
			   break;
		   case 'n':
			   source[i+1]='\n';
			   break;
		   case 't':
			   source[i+1]='\t';
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

int LoadKnownWebservers(const char *path)
{
	char tmp[100];
	int len=sizeof(tmp);
	nKnownWebservers=0;
	FILE *webservers=fopen(path,"r");
	if (!webservers) {
		return (0);
	}
	if (webservers)
	{
		while (!feof(webservers))
		{
			memset(tmp,'\0',sizeof(tmp));
			if (ReadAndSanitizeInput(webservers,tmp,len) && (strlen(tmp)>0) )
		 {
			 KnownWebservers=(char**)realloc(KnownWebservers,sizeof(char*)*(nKnownWebservers+1));
			 KnownWebservers[nKnownWebservers]=(char *)malloc(len+1);
			 strcpy(KnownWebservers[nKnownWebservers],tmp);
			 //            printf("anadiendo: !%s!\n",tmp);
			 nKnownWebservers++;
		 }

		}
		fclose(webservers);
	}

	return(nKnownWebservers);
}


//------------------------------------------------------------------------------

int LoadKnownRouters(const char *path)
{
	char tmp[100];
	int len=sizeof(tmp);
	FILE *webservers=fopen(path,"r");
	if (!webservers) {
		return(0);
	}

	nKnownRouters=0;
	if (webservers)
	{
		while (!feof(webservers))
		{
			memset(tmp,'\0',sizeof(tmp));
			if (ReadAndSanitizeInput(webservers,tmp,len) && (strlen(tmp)>1))
		 {
			 KnownRouters=(char**)realloc(KnownRouters,sizeof(char*)*(nKnownRouters+1));
			 KnownRouters[nKnownRouters]=(char *)malloc(len+1);
			 strcpy(KnownRouters[nKnownRouters],tmp);

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


int LoadWebForms(const char *path)
{
	FILE *webforms=fopen(path,"r");
	nWebforms=0;

	if (webforms) {
		char line[512];
		char tmp[512];

		int i;
		for(i=0;i<MAX_WEBFORMS;i++) memset((char *)&WEBFORMS[i],'\0',sizeof(struct _webform));
		while( (!feof(webforms)) && (nWebforms<MAX_WEBFORMS) )
		{
			//fgets(tmp,sizeof(tmp),webforms);

			//if ( (strlen(tmp)>6) && (tmp[0]!='#') && (tmp[0]!=';'))
			if (ReadAndSanitizeInput(webforms,tmp,sizeof(tmp)))
			{
				memset(line,'\0',sizeof(line));
				ValidateLine(tmp,line);

				if (strncmp(line,"Model=",6)==0)
					strncpy(WEBFORMS[nWebforms].model,line+6,sizeof(WEBFORMS[nWebforms].model));

				if (strncmp(line,"status=",7)==0)
					WEBFORMS[nWebforms].status=atoi(line+7);
				if (strncmp(line,"server=",7)==0) {
					strncpy(WEBFORMS[nWebforms].server,line+7,sizeof(WEBFORMS[nWebforms].server));
				}
				if (strncmp(line,"Matchstring=",12)==0)
					strncpy(WEBFORMS[nWebforms].matchstring,line+12,sizeof(WEBFORMS[nWebforms].matchstring));
				if (strncmp(line,"ValidateImage=",14)==0)
					strncpy(WEBFORMS[nWebforms].ValidateImage,line+14,sizeof(WEBFORMS[nWebforms].ValidateImage));
				if (strncmp(line,"authurl=",8)==0)
					strncpy(WEBFORMS[nWebforms].authurl,line+8,sizeof(WEBFORMS[nWebforms].authurl));
				if (strncmp(line,"authmethod=",11)==0)
					strncpy(WEBFORMS[nWebforms].authmethod,line+11,sizeof(WEBFORMS[nWebforms].authmethod));
				if (strncmp(line,"requireloginandpass=",20)==0)
					WEBFORMS[nWebforms].requireloginandpass=atoi(line+20);
				if (strncmp(line,"authform=",9)==0)
					strncpy(WEBFORMS[nWebforms].authform,line+9,sizeof(WEBFORMS[nWebforms].authform));
				if (strncmp(line,"validauthstring=",16)==0) {
					strncpy(WEBFORMS[nWebforms].validauthstring,line+16,sizeof(WEBFORMS[nWebforms].validauthstring));
				}
				if (strncmp(line,"validauthstringalt=",19)==0) {
					strncpy(WEBFORMS[nWebforms].validauthstringalt,line+19,sizeof(WEBFORMS[nWebforms].validauthstringalt));
				}


				if (strncmp(line,"invalidauthstring=",18)==0) {
					strncpy(WEBFORMS[nWebforms].invalidauthstring,line+18,sizeof(WEBFORMS[nWebforms].invalidauthstring));
					nWebforms++;
				}
				//optional Headers
				if (strncmp(line,"invalidauthstringalt=",21)==0) {
					strncpy(WEBFORMS[nWebforms-1].invalidauthstringalt,line+21,sizeof(WEBFORMS[nWebforms-1].invalidauthstringalt));
				}
				if (strncmp(line,"AdditionalHeader=",17)==0) {
					strncpy(WEBFORMS[nWebforms-1].AdditionalHeader,line+17,sizeof(WEBFORMS[nWebforms-1].AdditionalHeader));
				}
				if (strncmp(line,"UpdateCookie=",13)==0)
					WEBFORMS[nWebforms-1].UpdateCookie=atoi(line+13);
				if (strncmp(line,"InitialCookieURL=",17)==0) {
					strncpy(WEBFORMS[nWebforms-1].InitialCookieURL,line+17,sizeof(WEBFORMS[nWebforms-1].InitialCookieURL));	
				}
				if (strncmp(line,"ValidateAlternativeurl=",23)==0) {
					strncpy(WEBFORMS[nWebforms-1].ValidateAlternativeurl,line+23,sizeof(WEBFORMS[nWebforms-1].ValidateAlternativeurl));	
				}
				if (strncmp(line,"LoadAdditionalUrl=",18)==0) {
					strncpy(WEBFORMS[nWebforms-1].LoadAdditionalUrl,line+18,sizeof(WEBFORMS[nWebforms-1].LoadAdditionalUrl));	
				}
				if (strncmp(line,"ReconnectOnMatch=",17)==0) {
					strncpy(WEBFORMS[nWebforms-1].ReconnectOnMatch,line+17,sizeof(WEBFORMS[nWebforms-1].ReconnectOnMatch));	
				}


			}
		}
		fclose(webforms);
	}
	return(nWebforms);
}

//------------------------------------------------------------------------------
int LoadUserList(const char *path) {
	FILE *userlist;
	char *p;
	char user[200];

	nUsers=0;
	userlist=fopen(path,"r");


	if (userlist) {
		while( (!feof(userlist)) ) //&& (nUsers<MAX_USER_LIST) )
		{
			memset(user,'\0',sizeof(user));
			fgets(user,sizeof(user)-1,userlist);
			if ( (strlen(user)>1) && (user[0]!='#') )
			{
				p=user+strlen(user)-1;
				while ( (*p=='\r' ) || (*p=='\n') || (*p==' ') ) { p[0]='\0'; --p; }
				p=strchr(user,':');
				if (p)
				{
					userpass=(USERLIST*)realloc(userpass,sizeof(USERLIST)*(nUsers+1));
					memset(&userpass[nUsers],'\0',sizeof(USERLIST));
					p[0]='\0';
					strncpy(userpass[nUsers].UserName,user,sizeof(userpass[nUsers].UserName)-1);
					strncpy(userpass[nUsers].Password,p+1,sizeof(userpass[nUsers].Password)-1);
					nUsers++;
				}
			}
		}
		fclose(userlist);
	}
	return(nUsers);
}

/******************************************************************************/
int LoadSingleUserList(const char *path) {
	FILE *userlist;
	char *p;
	char user[200];
	int i=0;

	nLogins=0;



	userlist=fopen(path,"r");
	if (userlist) {
		while( (!feof(userlist)) ) //&& (nLogins<MAX_USER_LIST) )
		{
			fgets(user,sizeof(user)-1,userlist);
			if ( (strlen(user)>1) && (user[0]!='#') )
			{
				nLogins++;
			}
		} 
		fseek(userlist,0,SEEK_SET);
		logins=(USERLOGIN*)malloc(nLogins*sizeof(USERLOGIN));
		while( (!feof(userlist)) ) //&& (nLogins<MAX_USER_LIST) )
		{

			memset(user,'\0',sizeof(user));
			fgets(user,sizeof(user)-1,userlist);
			if ( (strlen(user)>1) && (user[0]!='#') )
			{
				p=user+strlen(user)-1;
				while ( (*p=='\r' ) || (*p=='\n') || (*p==' ') ) { p[0]='\0'; --p; }
				memset(logins[i].user,0,40);
				strncpy(logins[i].user,user,40-1);
				i++;
			}
		} 
		fclose(userlist);
	}

	return(nLogins);
}
/******************************************************************************/


int LoadWebservers(const char *path) {

	FILE *webservers;
	char tmp[512];
	char line[512];



	webservers=fopen(path,"r");
	if (!webservers) {
		return(0);
	}
	nvlist=-1;
	for(unsigned int i=0;i<sizeof(vlist)/sizeof(VLIST);i++) memset((char *)&vlist[i],'\0',sizeof(VLIST));
	while (!feof(webservers))
	{
		memset(tmp,'\0',sizeof(tmp));
		if ( ReadAndSanitizeInput(webservers,tmp,sizeof(tmp)) )
		{
			memset(line,'\0',sizeof(line));
			ValidateLine(tmp,line);

			if (strncmp(line,"vulnerability=",14)==0){
				nvlist++;
				strncpy(vlist[nvlist].vulnerability,line+14,sizeof(vlist[nvlist].vulnerability)-1);
			}
			if (strncmp(line,"status=",7)==0){
				vlist[nvlist].status=atoi(line+7);
			}
			if (strncmp(line,"server=",7)==0){
				strncpy(vlist[nvlist].server,line+7,sizeof(vlist[nvlist].server)-1);
			}
			if (strncmp(line,"url=",4)==0){
				strncpy(vlist[nvlist].url,line+4,sizeof(vlist[nvlist].url)-1);
			}
			if (strncmp(line,"Ignoresignature=",16)==0){
				strncpy(vlist[nvlist].Ignoresignature,line+16,sizeof(vlist[nvlist].Ignoresignature)-1);
			}
#define TOTALMATCHES vlist[nvlist].nMatch


			if (strncmp(line,"description=",12)==0){
				//RESERVAMOS MEMORIA PARA UN NUEVO MATCH
				vlist[nvlist].Match=(PMATCH)realloc(vlist[nvlist].Match,sizeof(MATCH)*(TOTALMATCHES+1));
				//PONEMOS A NULL LA VALIDACIoN
				//vlist[nvlist].Match[ TOTALMATCHES ].Validatestring=NULL;
				vlist[nvlist].Match[ TOTALMATCHES ].nstrings=0;
				//COPIAMOS LA DESCRIPCION
				strncpy( vlist[nvlist].Match[vlist[nvlist].nMatch].description,line+12,sizeof(vlist[nvlist].Match[vlist[nvlist].nMatch].description)-1);
				//INCREMENTAMOS EL CONTANDOR DE MATCHES
				vlist[nvlist].nMatch++;
			}

			if (strncmp(line,"Validatestring=",15)==0){
				//reservamos memoria para los matches..
				//vlist[nvlist].Match[ TOTALMATCHES -1].Validatestring=(char *)realloc(vlist[nvlist].Match[ TOTALMATCHES ].Validatestring, 200 * vlist[nvlist].Match[ TOTALMATCHES -1].nstrings+1);
				//copiamos la linea
				strncpy(vlist[nvlist].Match[TOTALMATCHES -1].Validatestring[vlist[nvlist].Match[ TOTALMATCHES -1].nstrings],line+15,sizeof(vlist[nvlist].Match[TOTALMATCHES -1].Validatestring[vlist[nvlist].Match[ TOTALMATCHES -1].nstrings])-1);
				vlist[nvlist].Match[ TOTALMATCHES  -1].nstrings++;
			}
			if (strncmp(line,"Ignorestring=",13)==0){
				//reservamos memoria para los matches..
				//vlist[nvlist].Match[ TOTALMATCHES -1].Validatestring=(char *)realloc(vlist[nvlist].Match[ TOTALMATCHES ].Validatestring, 200 * vlist[nvlist].Match[ TOTALMATCHES -1].nstrings+1);
				//copiamos la linea
				strcpy( vlist[nvlist].Match[TOTALMATCHES-1].Ignorestring-1,line+13);
			}


		}
	}
	nvlist++;
	fclose(webservers);
	return(nvlist);

}
//-----------------------------------------------------------------------------

int LoadRouterAuth(const char *path) {
	FILE *RouterAuth;
	char line[200];
	char *p;
	//int nRouterAuth=0;
	nRouterAuth=0;

	RouterAuth=fopen(path,"r");

	if (RouterAuth) {
		while (!feof(RouterAuth)) {
			fgets(line,sizeof(line)-1,RouterAuth);
			if ( (strlen(line)>5) && line[0]!='#' ) {
				p=line+strlen(line)-1;
				while ( (*p=='\r' ) || (*p=='\n') || (*p==' ') ) { p[0]='\0'; --p; }
				p=strtok(line,"|");
				FakeAuth[nRouterAuth].status=atoi(p);
				p=strtok(NULL,"|");
				strncpy(FakeAuth[nRouterAuth].server,p,sizeof(FakeAuth[nRouterAuth].server)-1);
				if ( (strlen(p)==1) && (p[0]=='*') ) FakeAuth[nRouterAuth].server[0]='\0';
				p=strtok(NULL,"|");
				strncpy(FakeAuth[nRouterAuth].authurl,p,sizeof(FakeAuth[nRouterAuth].authurl)-1);
				p=strtok(NULL,"|");
				strncpy(FakeAuth[nRouterAuth].method,p,sizeof(FakeAuth[nRouterAuth].method)-1);
				p=strtok(NULL,"|");
				if (p) strncpy(FakeAuth[nRouterAuth].postdata,p,sizeof(FakeAuth[nRouterAuth].postdata)-1);
				nRouterAuth++;
			}
		}
		fclose(RouterAuth);
	}
	return(nRouterAuth);
}
/******************************************************************************/



void usage(void) {
	printf(" Fast HTTP vulnerability Scanner (FHScan) v1.3\n");
	printf(" (c) Andres Tarasco - http://www.tarasco.org\n\n");
#ifdef __WIN32__RELEASE__
	printf("\n Usage: fhscan.exe  <parameters>\n\n");
#else
	printf("\n Usage: ./fhscan  <parameters>\n\n");
#endif
	printf("  --hosts   <ip1[-range][,hostname]>  (ex: --hosts 192.168.1.1-255,10.0.0.0-255.255,www.tarasco.org)\n");
	printf("  --threads <threads>                 (Number of threads.  default 10)\n");
	printf("  --ports <port>[,<port>,<port>,..]   (example --p 80,81,82,8080) default --ports 80\n");
	printf("  --sslports <port>[,<port>,<port>,..](example -P 443,1443)\n");
	printf("  --logdir <directory>                (Optional report log directory)\n");
	printf("\n Advanced options:\n");
	printf("  --timeout <timeout>                 (Connection Timeout. default 10)\n");
	printf("  --ipfile  <ipfile>                  (scan hosts from <ipfile>)\n");
#ifdef XML_LIBRARY
	printf("  --NmapFile <scan.xml>               (scan hosts and ports from an nmap result file)\n");
#endif
	printf("  --fulluserlist                      (Test biggest user list (slowest but more accurate)\n");   
	printf("  --verbose                           (show verbose fingerprint information, not only vulnerabilities)\n");
	printf("  --nobruteforce                      (Disable bruteforce (enabled by default) )\n");
	printf("  --proxyScanOnly                     (Only checks if the remote HTTP host is acting as a proxy server)\n");


	printf("  --csv                               (Formatted data is sent to stderr to support external applications)\n");
	printf("  --proxy http://host:port            (Allows FHScan to scan remote servers through proxy)\n");
	printf("  --proxyauth <username> <password>   (set username and password for the HTTP proxy)\n");

	printf("\n Other options\n");
	printf("  --update                            (Search online for updated signatures or application)\n");
	printf("  --EnableProxy                       (*New*  Starts an HTTP Proxy on port 8080 and displays requests)\n");
	printf("\n Manual request\n");
	printf("  --request http[s]://host[:p][/url]  (Do an HTTP request. example: --request http://www.tarasco.org/\n");
	printf("  --showlinks [link type]             (extract Hyperlinks from requested url)\n");
	printf("  --showresponse                      (Displays the remote HTTP response data)\n");
	printf("  --data  <data>                      (Add additional data to be submitted though an HTTP Request)\n");
	printf("  --vhost  <vhost>                    (Alternate Host header)\n");
	printf("  --method <method>                   (Alternate HTTP method. By default GET)\n");
	printf("\n");

	printf(" Example:\n");
	printf(" fhscan --ports 80 --sslports 443,1433 --hosts 192.168.0.1-192.168.1.254,10.0.0.0-255  --threads 200\n\n");
	return;

}
//-----------------------------------------------------------------------------



int LoadConfigurationFiles(HTTPAPI *api,int argc, char *argv[]){
	int i;
	char *p;
//	struct sockaddr_in ip1,ip2;
	int nhosts=0;
	char dbg[512];



	if (argc<2) {
		usage();
		return(1);
	}
	for (i=1;i<argc;i++)
	{
		if ( argv[i][0]=='-')
		{

			if (strcmp( argv[i],"--request")==0)
			{
				Fullurl = strdup(argv[i+1]);
				i++;
			} else
			if (strcmp( argv[i],"--showresponse")==0)
			{
				ShowResponse=1;
			} else

			if (strcmp( argv[i],"--showlinks")==0)
			{
				ShowLinks=1;
				if ( (argc>i+1) && (argv[i+1][0]!='-') ) {
					LinkType = strdup(argv[i+1]);
					i++;
				}

			} else

			if (strcmp( argv[i],"--method")==0)
			{
				method = strdup(argv[i+1]);
				i++;
			} else
			if (strcmp( argv[i],"--data")==0)
			{
				PostData = strdup(argv[i+1]);
				PostDataSize = (int)strlen(PostData);
				i++;
			} else
			if (strcmp( argv[i],"--vhost")==0)
			{
				vhost = strdup(argv[i+1]);
				i++;
			} else
			if (strcmp( argv[i],"--proxyScanOnly")==0)
			{
				proxyScanOnly = 1;
			} else


			if (strcmp( argv[i],"--nobruteforce")==0) {
				bruteforce=0;
			} else
			 if (strcmp( argv[i],"--EnableProxy")==0) {
				return(2);
			 } else
				if (strcmp(argv[i],"--update")==0) {
						UpdateFHScan(api); exit(1);
					} else
						if (strcmp( argv[i],"--fulluserlist")==0) {
							FullUserList=1;
						} else
							if (strcmp( argv[i],"--verbose")==0) {
								ShowAllhosts=1;
							} else
								if (strcmp( argv[i],"--logdir")==0) {
									strcpy(DirectoryLog,argv[i+1]);
									i++;
								} else
									if (strcmp( argv[i],"--csv")==0) {
										csv = 1;
									} else
										if ((strcmp( argv[i],"--ports")==0) || (strcmp( argv[i],"--port")==0) ) {
											p=strtok(argv[i+1],",");
											while (p!=NULL) {
												ports[nports].port=atoi(p);
												ports[nports].ssl=0;
												p=strtok(NULL,",");
												nports++;
											}
											i++;
										} else

											if ( (strcmp( argv[i],"--sslports")==0) || (strcmp( argv[i],"--sslport")==0) ){
												p=strtok(argv[i+1],",");
												while (p!=NULL) {
													ports[nports].port=atoi(p);
													ports[nports].ssl=1;
													p=strtok(NULL,",");
													nports++;
												}
												i++;
											} else


												if (strcmp( argv[i],"--threads")==0) {
													nthreads=atoi(argv[i+1]);
													i++;
												} else
													if (strcmp( argv[i],"--proxy")==0)
													{
                                                    	printf("estableciendo proxy...\n");
														char proxyhost[512];
														char proxyport[10];
														if ( sscanf( argv[i+1], "http://%[^:/]:%s", proxyhost, proxyport ) == 2 )
														{
															api->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigProxyHost,proxyhost);
															api->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigProxyPort,proxyport);
														}  else {
															printf(" [-] Invalid proxy parameter %s\n",argv[i+1]);
															printf(" [-] Should be http://host:port\n");
															return(1);
                                                        }

														i++;
													} else
														if (strcmp( argv[i],"--proxyauth")==0) {
															api->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigProxyUser,argv[i+1]);
															api->SetHTTPConfig(GLOBAL_HTTP_CONFIG,ConfigProxyPass,argv[i+2]);
															i+=2;
														} else

															if (strcmp( argv[i],"--ipfile")==0) 
															{
																ipfilepath=argv[i+1];
																ipfile=fopen(ipfilepath,"r");
																if (ipfile) {
																	printf("[+] Loaded ips from %s\n",argv[i+1]);
																} else {
																	printf("[-] Unable to load ips from %s\n",argv[i+1]);
																	usage();
																	return(1);
																}
																i++;
															} else
																#ifdef XML_LIBRARY
																if ( (strcmp( argv[i],"--NmapFile")==0) || (strcmp( argv[i],"--nmapfile")==0) )
																{
																	nmap = argv[i+1];
																	i++;
																} else 
																#endif
																if ( (strcmp( argv[i],"--hosts")==0) || (strcmp( argv[i],"--host")==0) )
																{
																	hosts= argv[i+1];																	
																	i++;
																} else {
																	usage();
																	printf("Invalid parameter %s\n",argv[i]);
																	return(1);
																}
		}
	}

	//manual requests
	if (Fullurl) {
         return(3);
	 }


	if (FullUserList) {
		i=LoadUserList("UserListMulti.ini");
	} else {
		i=LoadUserList("UserListMulti-simple.ini");
	}
	if (!i) {
		if (!csv) printf("[-] UserList file not found\n");
		return(1);
	} else {
		if (!csv) printf("[+] Loaded %i user/pass combinations\n",i);
	}
	/*   i=LoadIgnoreList("IgnoreList.ini");
	if (!i) {
	printf("[-] Unable to load Ignore List\n");
	return(1);
	} else {
	printf("[+] Loaded %i ignored webservers\n",i);
	}
	*/
	nRouterAuth=LoadRouterAuth("RouterAuth.ini");
	if (!nRouterAuth) {
		if (!csv) printf("[-] Unable to load Router Auth engine\n");
		return(1);
	} else {
		if (!csv) printf("[+] Loaded %i Router authentication schemes\n",nRouterAuth);
	}
	i=LoadWebForms("webforms.ini");
	if (!i) {
		if (!csv) printf("[-] Unable to load Webforms auth engine\n");
		return(1);
	} else {
		if (!csv) printf("[+] Loaded %i webform authentication schemes\n",i);
	}
	i=LoadSingleUserList("UserListSingle.ini");
	if (!i) {
		if (!csv) printf("[-] Unable to load Single login file\n");
		return(1);
	} else {
		if (!csv) printf("[+] Loaded %i Single Users\n",i);
	}

	i=LoadWebservers("Webservers.ini");
	if (!i) {
		if (!csv) printf("[-] Unable to load vulnerability database\n");
		return(1);
	} else {
		if (!csv) printf("[+] Loaded %i vulnerabilities\n",i);
	}


	i=LoadKnownWebservers("KnownWebservers.ini");
	if (!i) {
		if (!csv) printf("[-] Unable to load Known Webservers database\n");
		return(1);
	} else {
		if (!csv) printf("[+] Loaded %i Known Webservers\n",i);
	}

	i=LoadKnownRouters("KnownRouters.ini");
	if (!i) {
		if (!csv) printf("[-] Unable to load Known Routers database\n");
		return(1);
	} else {
		if (!csv) printf("[+] Loaded %i Known Routers\n",i);
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
			snprintf(dbg,sizeof(dbg)-1,"[+] Scanning hosts from ip file\n",nhosts);
			printf("%s",dbg);
		} else {
			/*
			char tmp[20];
			snprintf(tmp,sizeof(tmp)-1,"%s)\n",inet_ntoa(ip2.sin_addr));
			snprintf(dbg,sizeof(dbg)-1,"[+] Scanning %i hosts  (%s  - %s",nhosts,inet_ntoa(ip1.sin_addr),tmp);
			printf("%s",dbg);
			*/
		}
		
		
		snprintf(dbg,sizeof(dbg)-1,"[+] Scanning %i ports - bruteforce is %s\n",nports,bruteforce ? "active" : "Inactive");
		printf("%s",dbg);
		printf("\n");
	}






	return(0);
}



