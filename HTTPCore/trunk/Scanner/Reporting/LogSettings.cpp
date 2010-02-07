/*
Fast HTTP Auth Scanner - Logsettings.cpp
Creates HTML reports from tmpl.dat template

TODO:
- Rellenar la variable $FRECORDS con los parametros de cada fichero
*/


//#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include "../../HTTPCore/Build.h"
#include "../FHScan.h"
#include "LogSettings.h"

Threading lock;
#ifdef __WIN32__RELEASE__
SYSTEMTIME LogTime;
#else
#include <sys/stat.h>
#include <sys/types.h>
struct tm *LogTime;
#endif


PREPORT report=NULL;
HTTPCHAR files[][20]={ _T("index.html"),_T("devices.html"),_T("webservers.html"),_T("routerswp.html"),_T("routersup.html"),_T("routersnp.html"),_T("bruteforce.html") };
HTTPCHAR descs[][50]= {_T("Open ports"),_T("Devices"),_T("webservers"),_T("Routers with password"),_T("routers with unknown password"),_T("routers without password"),_T("Web vulnerabilities")};

extern FILE   *ipfile;
extern int ShowAllhosts;
extern int csv;
HTTPCHAR DirectoryLog[MAX_PATH+1]=_T("");
//extern FILE *LogFile;
//extern FILE *LogFiledebug;

#ifdef  __WIN32__RELEASE__
# if defined(_MSC_VER)
# else
#define _feof(a) ( (a->flags & _F_EOF) )
#define feof _feof
#endif
#endif


/**************************************************************************/
int CloseHTMLReport(void)
{
//return (0);
	//DeleteMutex(&lock);
	if (report) {
		for(int i=0;i<7;i++) {
			if (report[i].logfile)
			{
				fwrite(report[i].end,1,_tcslen(report[i].end),report[i].logfile);
				fclose(report[i].logfile);
			}
		}
		free(report);
		return(1);
	}
	return(0);
}
/**************************************************************************/
//int UpdateHTMLReport(HTTPSession* data, int FROM)
/**************************************************************************/
//http://www.cert.org/tech_tips/cgi_metacharacters.html
#if 0
void FixXSS(char *data, char *dst) {
	char *q;
	static char ok_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@ ";
	if (data)
    *dst='\0';
}
#endif

#define  ok_chars "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@ "
//__inline static void FixXSS(char *data) {while (*(data++)) { char *q=strchr(ok_chars,*data); *data=(q) ? *q :'_' ; }   }
/**************************************************************************/
/*******************************************************************************/
static int GetHtmlTitle(HTTPSession* data, HTTPCHAR *output, size_t dstSize) {

    HTTPCHAR *p,*q;
	HTTPCHAR *buffer;
	size_t BufferSize;// = (unsigned int ) strlen(buffer);

	if (data->response->DataSize == 0) {
    	*output=0;
        return(0);
	}
	buffer=data->response->Data;
	BufferSize =  _tcslen(buffer);

	if ( (buffer) && BufferSize>15) {
        for (unsigned int i=0;i<BufferSize-14;i++)
        {
			if (_tcsncicmp(buffer+i,_T("<title"),6)==0)
			{
				memset(output,_T('\0'),dstSize);
				p = _tcschr(buffer+i+6,_T('>'));
				if (p){					
					p++;
					q=_tcschr(p,_T('<'));
					memset(output,0,dstSize);
					if (q) {
						
						while ( (*p==_T('\r')) || (*p==_T('\n')) || (*p==_T(' ')) ) p++;
						if ( (q-p)<(int)dstSize) memcpy(output,p,q-p);
						else            memcpy(output,p,(dstSize-1)*sizeof(HTTPCHAR));
					} else {
						BufferSize = _tcslen(p);
						if (BufferSize>dstSize)
						{
							memcpy(output,p,(dstSize-1)*sizeof(HTTPCHAR));
						} else {
							memcpy(output,p,BufferSize*sizeof(HTTPCHAR));
						}
					}
					return(1);
				}
			}
        }
	}

	if ( (data->status==401) )
	{
			HTTPCHAR *lpTitle=data->response->GetHeaderValue(_T("WWW-Authenticate: Basic"),0);
			if (lpTitle)
			{
				HTTPCHAR *realm=_tcsstr(lpTitle,_T("realm=\""));
				if (realm){
					realm+=7;
					HTTPCHAR *q=_tcschr(realm,_T('\"'));
					if (q)
					{
						*q=0;
						memset(output,0,dstSize);
						_tcsncpy(output,realm,dstSize-1);
						free(lpTitle);
						return(1);
					}

				}
				free(lpTitle);
			}
	}
	*output='\0';
	return(0);
}
/*******************************************************************************/
int UpdateHTMLReport(HTTPSession* data,int FROM, HTTPCSTR UserName, HTTPCSTR Password, HTTPCHAR *url, HTTPCSTR VulnDescription)
{
//     return (0);

	HTTPCHAR buffer[4096]=_T("");
	HTTPCHAR tmp[2048];
	int j=0;
	HTTPCHAR *p;

	if ( (!data) || (!report)) {
		return(0);
	}



	if (report)
	{
		lock.LockMutex();
		HTTPCHAR title[512];

		GetHtmlTitle(data,(HTTPCHAR*)title,sizeof(title)/sizeof(HTTPCHAR));


		_sntprintf(buffer,sizeof(buffer)-1,_T("   <tr> <td><a href=\"%s://%s:%i%s\" target=\"_blank\">+</a>%s</td> <td>%i</td> <td>%i</td> <td>%s</td>"),data->NeedSSL ? _T("https") : _T("http") ,data->hostname,data->port,url ? url : _T("/"),data->hostname,data->port,data->status,title);
		fwrite(buffer,1,_tcslen(buffer),report[FROM].logfile);

		
		switch(FROM)
		{

		case MESSAGE_FINGERPRINT:
			if (ShowAllhosts) {
				if (csv) {
					_ftprintf(stdout,_T("FPRINT|%s|%i|%i|%s|%s\n"),data->hostname,data->port,data->status,title,data->server);
				} else {
					_tprintf(_T("FPRINT: %15s %5i %3i %s\n"),data->hostname,data->port,data->status,data->server);
				}
			}
			break;
		case MESSAGE_ROUTER_FOUND:
			if (csv) {
					_ftprintf(stdout,_T("ROUTER|%s|%i|%i|%s|%s\n"),data->hostname,data->port,data->status,title,data->server);
			} else {
				_tprintf(_T("ROUTER: %15s %5i %3i %s\n"),data->hostname,data->port,data->status,data->server);
			}
			break;
		case MESSAGE_WEBSERVER_FOUND:
			if (csv) {
					_ftprintf(stdout,_T("WEBSRV|%s|%i|%i|%s|%s\n"),data->hostname,data->port,data->status,title,data->server);
			} else {
				_tprintf(_T("WEBSRV: %15s %5i %3i %s\n"),data->hostname,data->port,data->status,data->server);
			}
			break;
		case MESSAGE_ROUTER_PASSFOUND:
//		case MESSAGE_WEBFORM_PASSFOUND:
			_sntprintf(buffer,sizeof(buffer)-1,_T("<td>%s</td> <td>%s</td> <td>%s</td> "),(UserName!=NULL) ? UserName : _T(""),(Password!=NULL) ? Password : _T(""),url);
			fwrite(buffer,1,_tcslen(buffer),report[FROM].logfile);

			if (csv) {
					_ftprintf(stdout,_T("RTPASS|%s|%i|%i|%s|%s|%s|%s|%s\n"),data->hostname,data->port,data->status,title,(UserName!=NULL) ? UserName : _T(""),(Password!=NULL) ? Password : _T(""),url,data->server);
			} else {
				_tprintf(_T("RTPASS: %15s %5i %3i %s %s %s %s\n"),data->hostname,data->port,data->status,(UserName!=NULL) ? UserName : _T(""),(Password!=NULL) ? Password : _T(""),url,data->server);
			}
			break;
		case MESSAGE_WEBFORMS_PASSNOTFOUND:  //router 401 & webform authentication

			_sntprintf(buffer,sizeof(buffer)-1,_T("<td>%s</td> "),url);
			fwrite(buffer,1,_tcslen(buffer),report[FROM].logfile);
			if (csv) {
					_ftprintf(stdout,_T("RUPASS|%s|%i|%i|%s|%s|%s\n"),data->hostname,data->port,data->status,title,url,data->server);
			} else {
				_tprintf(_T("RUPASS: %15s %5i %3i %s %s\n"),data->hostname,data->port,data->status,url,data->server);
			}
			break;
		case MESSAGE_ROUTER_NOPASSWORD:
			if (csv) {
					_ftprintf(stdout,_T("RNPASS|%s|%i|%i|%s|%s\n"),data->hostname,data->port,data->status,title,data->server);
			} else {
				_tprintf(_T("RNPASS: %15s %5i %3i %s\n"),data->hostname,data->port,data->status,data->server);
			}
			break;
		case MESSAGE_WEBSERVER_VULNERABILITY:
//		case MESSAGE_WEBSERVER_VULNERABILITY_AUTHNEEDED:
//		case MESSAGE_WEBSERVER_PASSFOUND:
			_sntprintf(buffer,sizeof(buffer)-1,_T("<td>%s</td> <td>%s</td> <td>%s</td> <td>%s</td> "),url,(UserName!=NULL) ? UserName : _T(""),(Password!=NULL) ? Password : _T(""),(VulnDescription!=NULL) ? VulnDescription : _T(""));
			fwrite(buffer,1,_tcslen(buffer),report[FROM].logfile);

			if (csv) {
					_ftprintf(stdout,_T("WEBVUL|%s|%i|%i|%s|%s|%s|%s|%s|%s\n"),data->hostname,data->port,data->status,title,(UserName!=NULL) ? UserName : _T(""),(Password!=NULL) ? Password : _T(""),url,(VulnDescription!=NULL) ? VulnDescription : _T(""),data->server);
			} else {
				_tprintf(_T("WEBVUL: %15s %5i %3i %s %s %s %s %s\n"),data->hostname,data->port,data->status,(UserName!=NULL) ? UserName : _T(""),(Password!=NULL) ? Password : _T(""),url,(VulnDescription!=NULL) ? VulnDescription : _T(""),data->server);
			}
			break;
		default:
			lock.UnLockMutex();
			return 0;
		}
			if ((VulnDescription) && ( (FROM == MESSAGE_WEBFORM_PASSFOUND) || (FROM == MESSAGE_ROUTER_PASSFOUND) || (FROM == MESSAGE_WEBFORM_PASSFOUND) || (FROM == MESSAGE_WEBFORMS_PASSNOTFOUND)) )
			{
				_sntprintf(tmp,sizeof(tmp)/sizeof(buffer)-1,_T(" (%s)"),VulnDescription);
			} 	else tmp[0]=_T('\0');
			_sntprintf(buffer,sizeof(buffer)-1,_T("<td id=\"IP%s\" onmouseover=\"testfunc(this.id);\" onmouseout=\"setVisibility('foo','none');\">%s %s "),data->hostname,data->server,tmp);
			fwrite(buffer,1,_tcslen(buffer),report[FROM].logfile);
			_sntprintf(buffer,sizeof(buffer)-1,_T("<div id=\"headers_IP%s\" class=\"hideme\"> "),data->hostname);
			fwrite(buffer,1,_tcslen(buffer),report[FROM].logfile);

			while (	p=data->response->GetHeaderValueByID(j++) ){
				fwrite(p,1,_tcslen(p),report[FROM].logfile);
				fwrite(_T("<br/>"),1,5*sizeof(HTTPCHAR),report[FROM].logfile);
				free(p);
			}
			fwrite(_T("</div></td>"),1,11*sizeof(HTTPCHAR),report[FROM].logfile);
			fwrite(_T("</tr>\n"),1,6*sizeof(HTTPCHAR),report[FROM].logfile);

			fflush( report[FROM].logfile);
			fflush(stdout);


		lock.UnLockMutex();
		return(1);
	}
	return(0);

}
/**************************************************************************/

int InitHTMLReport(
				   HTTPCHAR *path,
				   unsigned long currentip,
				   unsigned long endip,
				   int nports,
struct _ports *ports,
	int nthreads,
	int bruteforce,
	int fulluserlist,
	int vulnchecks) {

//return(0);
		//InitMutex(&lock);

#ifdef __WIN32__RELEASE__
		GetLocalTime(&LogTime);
#else
		time_t currenttime;
		char fecha[256];
		time(&currenttime);
		LogTime=gmtime(&currenttime);
#endif


		report=(PREPORT)malloc(sizeof(REPORT)*7);
		memset(report,'\0',   sizeof(REPORT)*7);

		FILE *TemplateHTML=_tfopen(_T("tmpl.dat"),_T("r"));
		if (!TemplateHTML) {
			if (!csv) {
				_tprintf(_T("[-] Error Loading tmpl.dat\n"));
			}
			free(report); report=NULL;
			return(0);
		}
		if (TemplateHTML) {
			HTTPCHAR tmp[4096*2];
			size_t readbytes;
			size_t total=0;
			HTTPCHAR *lpHTML=NULL;
#ifdef __WIN32__RELEASE__
			if (!*DirectoryLog) _sntprintf(DirectoryLog,sizeof(DirectoryLog),_T(".\\%4.4i-%2.2i-%2.2i--%2.2i%2.2i%2.2i"),LogTime.wYear,LogTime.wMonth,LogTime.wDay,LogTime.wHour,LogTime.wMinute,LogTime.wSecond);
			CreateDirectory(DirectoryLog,NULL);
#else
			if (!*DirectoryLog)  _tcsftime(DirectoryLog,sizeof(DirectoryLog)-1,_T("./%Y-%m-%d--%H%M%S"),LogTime);
			mkdir(DirectoryLog,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

#endif
#ifdef __WIN32__RELEASE__

#else

#endif
			//Read HTML Template
			while (!feof(TemplateHTML)) {
				memset((void*)tmp,0,sizeof(tmp));
				readbytes=fread(tmp,1,sizeof(tmp)/sizeof(HTTPCHAR)-1,TemplateHTML);
				//				printf("leidos: %i - Total: %i\n",readbytes,total);
				lpHTML=(HTTPCHAR *)realloc((HTTPCHAR *)lpHTML,(total+readbytes+1)*sizeof(HTTPCHAR));
				_tcsncpy(lpHTML+total,tmp,readbytes);
				total+=readbytes;
				lpHTML[total]='\0';
			}
			HTTPCHAR *opt;
			//Generate HTML Head from Template
			HTTPCHAR *where=lpHTML;
			do {
				opt=_tcschr(where,_T('$'));
				if (opt) {
					for(int i=0;i<7;i++) _tcsncat(report[i].header,where,opt-where);
					if (_tcsnccmp(opt+1,_T("HOSTPATH"),8)==0)
					{
						if (path!=NULL)
						{
							//snprintf(tmp,sizeof(tmp)-1,"<a href=\"file:\\\\%s\" target=\"_blank\">%s</a>",path,path);
							//printf("copiando: %s\n",tmp);
							//strcat(report[0].header,tmp);
							for(int i=0;i<7;i++) _tcscat(report[i].header,path);
							//						printf("queda: %s\n",report[0].header);
						} else
						{
							struct sockaddr_in client;
							client.sin_addr.s_addr=htonl(currentip);
							_sntprintf(tmp,sizeof(tmp)-1,_T(" %s"),inet_ntoa(client.sin_addr));
							for(int i=0;i<7;i++) _tcscat(report[i].header,tmp);
							if (currentip +1 != endip) {
								for(int i=0;i<7;i++) _tcscat(report[i].header,_T(" - "));
								client.sin_addr.s_addr=htonl(endip);

#ifdef _UNICODE								
								HTTPCHAR ipAddressW[15];
								_stprintf(ipAddressW,_T("%S"),inet_ntoa(client.sin_addr));								
								
								for(int i=0;i<7;i++) _tcscat(report[i].header,ipAddressW);//inet_ntoa(client.sin_addr));

#else
								for(int i=0;i<7;i++) _tcscat(report[i].header,inet_ntoa(client.sin_addr));
#endif
								
							}
						}
					} else
						if (_tcsnccmp(opt+1,_T("SCANDATE"),8)==0)
						{
	#ifdef __WIN32__RELEASE__
									_sntprintf(tmp,sizeof(tmp)-1,_T("%i/%i/%i - %i:%i "),LogTime.wMonth,LogTime.wDay,LogTime.wYear,LogTime.wHour,LogTime.wMinute);
#else
									_tcsftime(tmp,sizeof(tmp)-1,_T("./%m/%d/%Y  - %H%M"),LogTime);
#endif
									for(int i=0;i<7;i++) _tcscat(report[i].header,tmp);
						} else

						if (_tcsnccmp(opt+1,_T("HTTPPORT"),8)==0)
						{
							for(int j=0;j<nports;j++)
							{
								if (j!=0) for(int i=0;i<7;i++) _tcscat(report[i].header,_T(" / "));
								if (!ports[j].ssl) {
									_sntprintf(tmp,sizeof(tmp)-1,_T("HTTP %i"),ports[j].port);
								} else {
									_sntprintf(tmp,sizeof(tmp)-1,_T("HTTPS %i"),ports[j].port);
								}
									for(int i=0;i<7;i++) _tcscat(report[i].header,tmp);

							}
						} else

								if (_tcsnccmp(opt+1,_T("NTHREADS"),8)==0)
								{
									_sntprintf(tmp,sizeof(tmp)-1,_T("%i"),nthreads);
									for(int i=0;i<7;i++) _tcscat(report[i].header,tmp);
									//strcat(report[i].header,"1");

								}
								if (_tcsnccmp(opt+1,_T("BRUTEFOR"),8)==0)
								{
									if (bruteforce) {
										for(int i=0;i<7;i++) _tcscat(report[i].header,_T("class=\"input\" >BruteForce"));
									} else {
										for(int i=0;i<7;i++) _tcscat(report[i].header,_T("class=\"inputstrike\" >BruteForce"));
									}
								} else
									if (_tcsnccmp(opt+1,_T("FULLUSER"),8)==0)
									{
										if (fulluserlist) {
											for(int i=0;i<7;i++) _tcscat(report[i].header,_T("class=\"input\" >Full Users list"));
										} else {
											for(int i=0;i<7;i++) _tcscat(report[i].header,_T("class=\"input\" > Simple Users List"));
										}
									} else
										if (_tcsnccmp(opt+1,_T("VULNCHEC"),8)==0)
										{
											if (vulnchecks) {
												for(int i=0;i<7;i++) _tcscat(report[i].header,_T("class=\"input\" >Vulnerability Checks"));
											} else {
												for(int i=0;i<7;i++) _tcscat(report[i].header,_T("class=\"inputstrike\" >Vulnerability Checks"));
											}

										} else
											if (_tcsnccmp(opt+1,_T("FOPTIONS"),8)==0)
											{
												for (int i=1; i < 7; i++) {
													_tcsncpy(report[i].header,report[i].header,sizeof(report[i].header)-1);
												}
												for(int i=0;i<7;i++)
												{
													for(int j=0;j<7;j++) {
														if (i==j) {
															_sntprintf(tmp,sizeof(tmp)-1,_T("  <li><a class=\"active\" href=\"%s\">%s</a></li>\n"),files[j],descs[j]);
														} else {
															_sntprintf(tmp,sizeof(tmp)-1,_T("  <li><a href=\"%s\">%s</a></li>\n"),files[j],descs[j]);
														}
														_tcscat(report[i].header,tmp);
													}
												}
											} else
												if (_tcsnccmp(opt+1,_T("FRECORDS"),8)==0) {
													for(int i=0;i<7;i++) {
														//if (i!=0) strncat(report[i].header,where,opt-where);
														//Shared columns
														_tcscat(report[i].header,_T("    <td width=\"100\" height=\"20\" class=\"field\">host</td>\n"));
														_tcscat(report[i].header,_T("    <td width=\"40\" class=\"field\">port</td>\n"));
														_tcscat(report[i].header,_T("    <td width=\"90\" class=\"field\">status code </td>\n"));
														_tcscat(report[i].header,_T("    <td width=\"150\" class=\"field\">HTML Title </td>\n"));

														switch(i) {
															case 0:
															case 1:
															case 2:
															case 5:
																_tcscat(report[i].header,_T("    <td class=\"field\">banner</td>\n"));
																break;
															case 3:
																_tcscat(report[i].header,_T("    <td class=\"field\">user</td>\n"));
																_tcscat(report[i].header,_T("    <td class=\"field\">password</td>\n"));
																_tcscat(report[i].header,_T("    <td class=\"field\">path</td>\n"));
																_tcscat(report[i].header,_T("    <td class=\"field\">banner</td>\n"));
																break;
															case 4:
																_tcscat(report[i].header,_T("    <td width=\"150\" class=\"field\">path</td>\n"));
																_tcscat(report[i].header,_T("    <td width=\"139\" class=\"field\">banner</td>\n"));
																break;
															case 6:
																_tcscat(report[i].header,_T("    <td width=\"94\" class=\"field\">path</td>\n"));
																_tcscat(report[i].header,_T("    <td width=\"58\" class=\"field\">user</td>\n"));
																_tcscat(report[i].header,_T("    <td width=\"70\" class=\"field\">password</td>\n"));
																_tcscat(report[i].header,_T("    <td width=\"194\" class=\"field\">description</td>\n"));
																_tcscat(report[i].header,_T("    <td width=\"148\" class=\"field\">banner</td>\n"));
																break;
														}

													}
												} else
													//END OF HEADER - WRITE TAIL INFORMATION
													if (_tcsnccmp(opt+1,_T("RECORDDT"),8)==0)
													{
														for(int i=0;i<7;i++) {
															//char foo[1024];
															//printf("END(%i): %s\n-------------\n",i,opt+9);
															_tcsncpy(report[i].end,opt+9,sizeof(report[i].end)-1);
#ifdef __WIN32__RELEASE__
															_sntprintf(tmp,sizeof(tmp)-1,_T("%s\\%s"),DirectoryLog,files[i]);
#else
															snprintf(tmp,sizeof(tmp)-1,"%s/%s",DirectoryLog,files[i]);
#endif
															//printf("Abriendo: %s\n",tmp);
															report[i].logfile=_tfopen(tmp,_T("w"));
															if (!report[i].logfile) {
																free(report);
																report=NULL;
																return(0);
															}
															fwrite(report[i].header,1,_tcslen(report[i].header),report[i].logfile);
															fflush(report[i].logfile);
														}
														free(lpHTML);
														fclose(TemplateHTML);
														return(1);
													}
													where=opt+9;
				} else {
					for(int i=0;i<7;i++) _tcsncat(report[i].header,where,_tcslen(where));
				}
			} while (opt);
			free(lpHTML);
			fclose(TemplateHTML);
			return(1);
		}

		return(1);
}
/***************************************************************/


