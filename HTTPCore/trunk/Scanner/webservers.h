#ifndef _WEBSERVERS_H
#define __WEBSERVERS_H

#include "FHScan.h"
#include "estructuras.h"
int CheckVulnerabilities(HTTPAPI *api,HTTPHANDLE HTTPHandle, HTTPSession* data,int nLogins, USERLIST *userpass);

#endif
