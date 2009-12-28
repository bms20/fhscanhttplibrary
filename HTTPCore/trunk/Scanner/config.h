#ifndef __CONFIGURATION_FILE
#define __CONFIGURATION_FILE

#include "FHScan.h"

#include <stdio.h>
#ifdef __WIN32__RELEASE__
 #include <windows.h>
#endif

int LoadConfigurationFiles(HTTPAPI *api,int argc, HTTPSTR argv[]);
int LoadKnownWebservers(HTTPCSTR path);
int LoadKnownRouters(HTTPCSTR path);
int LoadWebForms(HTTPCSTR path);
int LoadUserList(HTTPCSTR path);
int LoadSingleUserList(HTTPCSTR path);
int LoadIgnoreList(HTTPCSTR path);
int LoadWebservers(HTTPCSTR path) ;
int LoadRouterAuth(HTTPCSTR path) ;


#endif
