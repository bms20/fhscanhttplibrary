#ifndef _INPUT_HOSTS_
#define _INPUT_HOSTS_

#include <stdio.h>    // to get "printf" function
#include <stdlib.h>   // to get "free" function

int ParseNmapXMLFile(char *lpFilename);
int ParseHosts( char *lphosts);
int Parseipfile(FILE *ipfile);
int ReadAndSanitizeInput(FILE *file, char *buffer,int len); 

typedef struct _targets {
	unsigned long currentip;
	//unsigned long endip;
	char		 *hostname;
	unsigned int port;
	int			 ssl;
} TARGETS, *PTARGETS;


#endif