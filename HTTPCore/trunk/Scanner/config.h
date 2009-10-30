#ifndef __CONFIGURATION_FILE
#define __CONFIGURATION_FILE

#include "FHScan.h"

#include <stdio.h>
#ifdef __WIN32__RELEASE__
 #include <windows.h>
#endif

int LoadConfigurationFiles(HTTPAPI *api,int argc, char *argv[]);
int LoadKnownWebservers(const char *path);
int LoadKnownRouters(const char *path);
int LoadWebForms(const char *path);
int LoadUserList(const char *path);
int LoadSingleUserList(const char *path);
int LoadIgnoreList(const char *path);
int LoadWebservers(const char *path) ;
int LoadRouterAuth(const char *path) ;


#endif
