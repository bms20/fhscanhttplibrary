/*
 Copyright (C) 2012  Tarlogic Web intruder (TarWI).
 Andres Tarasco - http://www.tarlogic.com

 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.
 3. All advertising materials mentioning features or use of this software
 must display the following acknowledgement:
 This product includes software developed by Andres Tarasco fhscan
 project and its contributors.
 4. Neither the name of the project nor the names of its contributors
 may be used to endorse or promote products derived from this software
 without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.
 */
#ifndef _CONFIG_H_
#define _CONFIG_H_
#include "../HTTPCore/HTTP.h"
#include <stdio.h>

#define MAX_HEADERS 10
typedef struct Resource {
	HTTPSTR host;
	HTTPSTR VirtualHost;
	int port;
	HTTPSTR path;
	int SSLRequest;
	HTTPCHAR HTTPMethod[20];
	Resource(void);
	~Resource();
} RESOURCE,*PRESOURCE;

typedef struct _credentials
{
	uint64 *LastUsedTime;
	HTTPCHAR **login;
	unsigned short *passwordFound;
	unsigned short totalPasswordsFound;
	HTTPCHAR **password;
	unsigned int nPasswords;
	unsigned int nLogins;
	_credentials(void);
	~_credentials();
} CREDENTIAL, *PCREDENTIAL;

typedef struct _config {
public:
	HTTPHANDLE *HTTPHandle;
	HTTPAPI **api;
	PRESOURCE resource;
	CREDENTIAL credential;
	int getInformation;
	HTTPCHAR CustomCookie[4096];
	HTTPCHAR Domain[512];
	HTTPCHAR AdditionalHeaders[4096];
	int ThreadNumber;
	int MaxAttempts ;
	int WaitTime;
	int FakeSourceAddress;
	int SingleBruteforceAttack;
	int StopAfterPasswordFound;
	int ResumeIndex;


	_config(void);
	~_config();

} CONFIG,*PCONFIG;


void usage();
int ParseUrl(HTTPCHAR *Fullurl,PRESOURCE resource);
PCONFIG LoadConfigurationFiles(int argc, HTTPCHAR *argv[]);
#endif