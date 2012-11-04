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
#include "config.h"
#include "information.h"

#define DIE();  usage();delete config; return(NULL);

_credentials::_credentials(void) {
	LastUsedTime = NULL;
	login = NULL;
	password = NULL;
	nLogins = 0;
	nPasswords = 0;
	passwordFound = NULL;
	totalPasswordsFound = 0;

}

_credentials::~_credentials() {
	if (LastUsedTime) {
		free(LastUsedTime);
		LastUsedTime = NULL;
	}
	if (login) {
		for (unsigned int i = 0; i < nLogins; i++) {
			free(login[i]);
			login[i] = NULL;
		}
		free(login);
		login = NULL;
	}
	if (password) {
		for (unsigned int i = 0; i < nPasswords; i++) {
			free(password[i]);
			password[i] = NULL;
		}
		free(password);
		password = NULL;
	}
	nLogins = 0;
	nPasswords = 0;
	if (passwordFound) {
		free(passwordFound);
		passwordFound = NULL;
	}
}

Resource::Resource(void) {
	host = NULL;
	VirtualHost = NULL;
	path = NULL;
	port = 0;
	SSLRequest = 0;
	_tcscpy(HTTPMethod, _T("GET"));

}

Resource::~Resource() {
	if (host) {
		free(host);
		host = NULL;
	}
	if (VirtualHost) {
		free(VirtualHost);
		VirtualHost = NULL;
	}
	if (path) {
		free(path);
		path = NULL;
	}
}

_config::_config(void) {
	getInformation = 0;
	CustomCookie[0] = _T('\0');
	Domain[0] = _T('\0');
	ThreadNumber = 4;
	MaxAttempts = 4;
	WaitTime = 0;
	FakeSourceAddress = 0;

	resource = new Resource;
	HTTPHandle = NULL;
	api = NULL;
	SingleBruteforceAttack = 0;
	StopAfterPasswordFound = 1;
	ResumeIndex = 0;
	*AdditionalHeaders = 0;
}

_config::~_config() {
	delete resource;
	if (api) {
		for (int i = 0; i < ThreadNumber; i++) {
			delete api[i];
		}
		free(api);
		api = NULL;
	}

	if (HTTPHandle) {
		free(HTTPHandle);
		HTTPHandle = NULL;
	}
	resource = NULL;
}

void usage() {
	_tprintf(_T
		("Syntax: Tarwi [-i| [-l|L[m] LOGINS[FILE]] [-p|P PASS[FILE]]  [-d DOMAIN]] [options] -u http[s]://server[:PORT][/URI]]\r\n")
		);
	_tprintf(_T("Options\r\n"));
	_tprintf(_T
		("-u URL         Remote HTTP[s] server url (http[s]://192.168.0.1/uri)\r\n")
		);
	_tprintf(_T
		("-i             No bruteforce. Just gather information from the remote host\r\n")
		);
	_tprintf(_T
		("-g PROXY       HTTP proxy Gateway (http://192.168.0.254:3180)\r\n"));
	_tprintf(_T("-T THREADS     HTTP Threads (default 4)\r\n"));
	_tprintf(_T("\r\nCredential configuration:\r\n"));
	_tprintf(_T
		("-l LOGIN       Login with LOGIN name (comma separated logins)\r\n"));
	_tprintf(_T
		("-L[m] FILE     Load several logins from FILE (by default user.txt is used)\r\n")
		);
	_tprintf(_T
		("               The 'm' flag forces to read users and passwords from the same file (user:pass)\r\n")
		);
	_tprintf(_T
		("-p PASS        Try PASS as password  (comma separated passwords)\r\n")
		);
	_tprintf(_T
		("-P FILE        Load several passwords from FILE (by default pass.txt is used)\r\n")
		);
	_tprintf(_T
		("-d DOMAIN      Optional domain name, when targeting NTLM authentication\r\n")
		);

	_tprintf(_T("\r\nAttack configuration:\r\n"));
	_tprintf(_T
		("-m MAXATTEMPTS Limit the number of attempts to prevent account lockout (use with -w. default 4).\r\n")
		);
	_tprintf(_T
		("-w WAITTIME    Set the number of seconds the bruteforce should be paused when maxattempts is reached\r\n")
		);
	_tprintf(_T
		("-r POS         Resume attack using POS as the username index (example -r 50)\r\n")
		);
	_tprintf(_T
		("-s             Single account bruteforce (each username is tested only against one password)\r\n")
		);
	_tprintf(_T("-S             Do not STOP after a password is located\r\n"));

	_tprintf(_T("\r\nProtocol configuration\r\n"));
	_tprintf(_T
		("-M METHOD      HTTP Method (by default \"GET\" is used).\r\n"));
	_tprintf(_T("-c COOKIE      Use specific cookie ( PHPSESSID=foooo )\r\n"));
	_tprintf(_T("-C             Automatically handle cookies\r\n"));
	_tprintf(_T
		("-H HEADERS     Additional comma separated headers (-H \"TestHeader: aaa\",\"Header2: bbb\"\r\n")
		);
	_tprintf(_T("-R             Automatically handle HTTP redirects\r\n"));
	_tprintf(_T("-v VHOST       Set request to specific virtual host\r\n"));
	_tprintf(_T("-f             Fake Source Address headers\r\n"));

	_tprintf(_T("\r\n\r\n"));
	_tprintf(_T("Examples:\r\n"));
	_tprintf(_T("  Tarwi -i -u http://192.168.0.1/\r\n"));
	_tprintf(_T
		("  Tarwi -l Administrator -P pass.txt -d Tarlogic.local -m 5 -w 900 -u http://192.168.0.1/admin\r\n")
		);
	_tprintf(_T
		("  Tarwi -L users.txt -P pass.txt -u http://192.168.0.1/admin\r\n"));
	_tprintf(_T
		("  Tarwi -s  -l admin,root -p admin,root -u http://192.168.0.1/admin\r\n")
		);

}

int ReadAndSanitizeInput(FILE *file, char *buffer, int len) {
	// read a line from a file stream, and removes '\r' and '\n'
	// if the line is not a comment, true is returned
	fgets(buffer, len, file);
	buffer[len - 1] = '\0';
	unsigned int bufferSize = (unsigned int) strlen(buffer);
	if ((bufferSize > 3) && buffer[0] != '#' && buffer[0] != ';') {
		char *p = buffer + bufferSize - 1;
		while ((*p == '\r') || (*p == '\n') || (*p == ' ')) {
			p[0] = '\0';
			--p;
		}
		return (1);
	}
	return (0);
}

void AddUser(HTTPCHAR *user, PCONFIG config) {
	config->credential.login = (HTTPCHAR * *)realloc(config->credential.login,
		sizeof(HTTPCHAR * *)*(config->credential.nLogins + 1));
	if (_tcscmp(user, _T("<blank>")) == 0) {
		config->credential.login[config->credential.nLogins] = _tcsdup(_T(""));
	}
	else {
		config->credential.login[config->credential.nLogins] = _tcsdup(user);
	}
	config->credential.LastUsedTime =
		(uint64*)realloc(config->credential.LastUsedTime,
		sizeof(uint64) * (config->credential.nLogins + 1));
	config->credential.LastUsedTime[config->credential.nLogins] = 0;

	config->credential.passwordFound =
		(unsigned short *)realloc(config->credential.passwordFound,
		sizeof(unsigned short) * (config->credential.nLogins + 1));
	config->credential.passwordFound[config->credential.nLogins] = 0;
	config->credential.nLogins++;
}

void AddPassword(HTTPCSTR password, PCONFIG config) {
	config->credential.password =
		(HTTPCHAR * *)realloc(config->credential.password,
		sizeof(HTTPCHAR * *)*(config->credential.nPasswords + 1));
	if (_tcscmp(password, _T("<blank>")) == 0) {
		config->credential.password[config->credential.nPasswords] =
			_tcsdup(_T(""));
	}
	else {
		config->credential.password[config->credential.nPasswords] =
			_tcsdup(password);
	}
	config->credential.nPasswords++;
}

int LoadConfig(HTTPCSTR UserFile, HTTPCSTR PasswordFile, PCONFIG config) {

	char line[100];
	HTTPCSTR filename = UserFile;
	if (!filename)
		filename = PasswordFile;

	FILE *dataFile = _tfopen(filename, _T("r"));

	if (dataFile) {
		if (dataFile) {
			while (!feof(dataFile)) {
				memset(line, '\0', sizeof(line));
				if (ReadAndSanitizeInput(dataFile, line, sizeof(line) - 1) &&
					(strlen(line) > 1)) {

#ifdef _UNICODE
					HTTPCHAR* lpoutputW = (HTTPCHAR*)malloc(strlen(line) + 1);
					MultiByteToWideChar(CP_UTF8, 0, line, strlen(line),
						lpoutputW, strlen(line) + 1);
					lpoutputW[strlen(line) - 1] = 0;
					if (UserFile)
						AddUser(lpoutputW, config);
					else
						AddPassword(lpoutputW, config);
					free(lpoutputW);
#else
					if ((UserFile) && (PasswordFile)) {
						HTTPCHAR *p = _tcstok(line, _T(":"));
						if (p) {
							AddUser(p, config);
							p = _tcstok(NULL, _T(":"));
							if (p) {
								AddPassword(p, config);
							}
							else {
								AddPassword(_T(""), config);
							}
						}
					}
					else {
						if (UserFile)
							AddUser(line, config);
						else
							AddPassword(line, config);
					}

#endif

				}
			}
			fclose(dataFile);
		}
	}
	return (1);

}

int ParseUrl(HTTPCHAR *Fullurl, PRESOURCE resource) {
	resource->SSLRequest = ((Fullurl[4] == _T('s')) || (Fullurl[4] == _T('S')));
	HTTPCHAR *host = (HTTPSTR)Fullurl + 7 + resource->SSLRequest;
	HTTPSTR p = _tcschr(host, _T(':'));

	if (!p) {
		if (resource->SSLRequest) {
			resource->port = 443;
		}
		else {
			resource->port = 80;
		}
		HTTPSTR newpath = _tcschr(host, _T('/'));
		if (newpath) {
			resource->path = _tcsdup(newpath);
			*newpath = 0;
		}
		else {
			resource->path = _tcsdup(_T("/"));
		}
	}
	else {
		*p = 0;
		p++;
		HTTPSTR newpath = _tcschr(p, _T('/'));
		if (newpath) {
			resource->path = _tcsdup(newpath);
			*newpath = 0;
			resource->port = _tstoi(p);
		}
		else {
			resource->port = _tstoi(p);
			resource->path = _tcsdup(_T("/"));
		}
	}
	resource->host = _tcsdup(host);
	// resource->host = _tcsdup(_T("2002::::c0a8:0001::"));
	// _tprintf(_T("[+] Target Information:\r\n"),resource->host);
	_tprintf(_T("[+] Remote host: %s\r\n"), resource->host);
	_tprintf(_T("[+] Remote port: %i\r\n"), resource->port);
	_tprintf(_T("[+] Remote resource: %s\r\n"), resource->path);
	_tprintf(_T("[+] SSL enable: %s\r\n\r\n"), resource->SSLRequest ?
		_T("TRUE") : _T("FALSE"));
	return (1);

}

PCONFIG LoadConfigurationFiles(int argc, HTTPCHAR *argv[]) {
	if (argc < 2) {
		usage();
		return (NULL);
	}

	PCONFIG config = new CONFIG;

	// First we lock for threads
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == _T('-')) {
			if (argv[i][1] == _T('T')) {
				config->ThreadNumber = _tstoi(argv[++i]);

				break;
			}
		}
	}
	config->HTTPHandle =
		(HTTPHANDLE*)malloc(config->ThreadNumber*sizeof(HTTPHANDLE));
	config->api = (HTTPAPI * *)malloc(config->ThreadNumber*sizeof(void*));
	for (int i = 0; i < config->ThreadNumber; i++) {
		config->api[i] = new HTTPAPI;
	}

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == _T('-')) {
			switch (argv[i][1]) {
			case _T('T'):
				i++;
				break;
			case _T('i'):
				if (!config->getInformation) {
					config->getInformation = 1;
				}
				else {
					DIE();
				}
				break;
			case _T('g'):
				if (argc > i + 1) {
					HTTPCHAR proxyhost[512];
					HTTPCHAR proxyport[10];
					if (_stscanf(argv[++i], _T("http://%[^:]:%s"), proxyhost,
						proxyport) == 2) {
						_tprintf(_T
							("[+] Stablishing Proxy Host Configuration: %s\n"),
							proxyhost);
						for (int i = 0; i < config->ThreadNumber; i++)
							config->api[i]->SetHTTPConfig(GLOBAL_HTTP_CONFIG,
							ConfigProxyHost, proxyhost);
						_tprintf(_T
							("[+] Stablishing Proxy Port Configuration: %s\n"),
							proxyport);
						for (int i = 0; i < config->ThreadNumber; i++)
							config->api[i]->SetHTTPConfig(GLOBAL_HTTP_CONFIG,
							ConfigProxyPort, proxyport);
					}
					else {

						_tprintf(_T(" [-] Invalid proxy parameter %s\n"),
							argv[i]);
						_tprintf(_T(" [-] Should be http://host:port\n"));
						DIE();
					}
				}
				else {
					DIE();
				}
				break;
			case _T('u'):
				if (!config->resource->port) {
					ParseUrl(argv[++i], config->resource);
				}
				else {
					DIE();
				}
				break;
			case _T('c'):
				if (argc > i + 1) {
					_tcscpy(config->CustomCookie, argv[++i]);
				}
				else {
					DIE();
				}
				break;
			case _T('C'):
				for (int threads = 0; threads < config->ThreadNumber; threads++)
					config->api[threads]->SetHTTPConfig(GLOBAL_HTTP_CONFIG,
					ConfigCookieHandling, 1);
				break;
			case _T('r'):
				config->ResumeIndex = _tstoi(argv[i + 1]);
				i++;
				break;
			case _T('R'):
				for (int threads = 0; threads < config->ThreadNumber; threads++)
					config->api[threads]->SetHTTPConfig(GLOBAL_HTTP_CONFIG,
					ConfigAutoredirect, 1);
				break;
			case _T('d'):
				if (argc > i + 1) {
					_tcscpy(config->Domain, argv[++i]);
				}
				else {
					DIE();
				}
				break;
			case 's':
				config->SingleBruteforceAttack = 1;
				break;
			case _T('m'):
				if (argc > i + 1) {
					config->MaxAttempts = _tstoi(argv[++i]);
				}
				else {
					DIE();
				}
				break;
			case _T('M'):
				if (argc > i + 1) {
					_tcscpy(config->resource->HTTPMethod, argv[++i]);
				}
				else {
					DIE();
				}
				break;
			case _T('w'):
				if (argc > i + 1) {
					config->WaitTime = _tstoi(argv[++i]) * 1000 + 150;
					// add additional 150ms
				}
				else {
					usage();
					return (0);
				}
				break;
			case _T('v'):
				if (argc > i + 1) {
					if ((config->api[0]->GetHTTPConfig(GLOBAL_HTTP_CONFIG,
						ConfigProxyHost)) && (!config->resource->SSLRequest)) {
						_tprintf(_T
							("[-] Unable to set a virtual host header with HTTP proxy (parametr -v ignored)\r\n")
							);
						i++;
					}
					else {
						config->resource->VirtualHost = _tcsdup(argv[++i]);
					}
				}
				else {
					DIE();
				}
				break;
			case _T('l'):
				if (argc > i + 1) {
					HTTPCHAR *trozo = _tcstok(argv[++i], _T(","));
					while (trozo != NULL) {
						AddUser(trozo, config);
						trozo = _tcstok(NULL, _T(","));
					}
				}
				else {
					DIE();
				}
				break;
			case _T('H'):
				if (argc > i + 1) {
					HTTPCHAR *trozo = _tcstok(argv[++i], _T(","));
					while (trozo != NULL) {
						_tcscat(config->AdditionalHeaders, trozo);
						_tcscat(config->AdditionalHeaders, _T("\r\n"));
						trozo = _tcstok(NULL, _T(","));
					}
				}
				else {
					DIE();
				}
				break;
			case _T('L'):
				if (argc > i + 1) {
					if ((strlen(argv[i]) == 3) && (argv[i][2] == 'm')) {
						LoadConfig(argv[i + 1], argv[i + 1], config);
						config->SingleBruteforceAttack = 1;
						i++;
					}
					else {
						LoadConfig(argv[++i], NULL, config);
					}

				}
				else {
					DIE();
				}
				break;
			case _T('p'):
				if (argc > i + 1) {
					HTTPCHAR *trozo = _tcstok(argv[++i], _T(","));
					while (trozo != NULL) {
						AddPassword(trozo, config);
						trozo = _tcstok(NULL, _T(","));
					}
				}
				else {
					DIE();
				}
				break;
			case _T('P'):
				if (argc > i + 1) {
					LoadConfig(NULL, argv[++i], config);
				}
				else {
					DIE();
				}
				break;
			case _T('S'):
				config->StopAfterPasswordFound = 0;
				break;
			case _T('f'):
				config->FakeSourceAddress = 1;
				break;
			default:
				_tprintf(_T("[-] Invalid parameter %s\r\n\r\n"), argv[i]);
				DIE();
				break;
			}
		}
	}
	if (!config->resource->host) {
		DIE();
	}

	for (int threads = 0; threads < config->ThreadNumber; threads++) {
		config->HTTPHandle[threads] =
			config->api[threads]->InitHTTPConnectionHandle
			(config->resource->host, config->resource->port,
			config->resource->SSLRequest);
		if (config->HTTPHandle[threads] == INVALID_HHTPHANDLE_VALUE) {
			_tprintf(_T("[-] ERROR - Unable to resolve the remote Host\n"));
			delete config;
			return (NULL);
		}
		if (config->CustomCookie[0]) {
			config->api[threads]->SetHTTPConfig(config->HTTPHandle[threads],
				ConfigCookie, config->CustomCookie);
		}
		if (config->resource->VirtualHost) {
			config->api[threads]->SetHTTPConfig(config->HTTPHandle[threads],
				ConfigHTTPHost, config->resource->VirtualHost);
		}
	}

	int ret = GetInformation(config->api[0], config->HTTPHandle[0],
		config->resource->host, config->resource->port, config->resource->path,
		config->resource->SSLRequest, config->resource->HTTPMethod,
		config->AdditionalHeaders);
	if ((!ret) || (config->getInformation)) {
		delete config;
		return (NULL);
	}

	if ((ret & NTLM_AUTH) && (config->WaitTime == 0)) {

		_tprintf(_T("\r\n"));
		_tprintf(_T
			("[-] Warning. The remote host supports NTLM auth. No lock policy was selected\r\n")
			);
		_tprintf(_T
			("[-] Warning. Remote computer or domain accounts can be locked\r\n"
			));
		_tprintf(_T
			("[-] Warning. Press any key to continue at your own risk\r\n"));
		_tprintf(_T
			("[-] Warning. Or cancel the bruteforce attack with CTRL+C (recommended -m and -w flags)\r\n")
			);
		getchar();
	}

	if (config->credential.nLogins == 0) {
		LoadConfig(_T("users.txt"), NULL, config);
	}

	if (config->credential.nPasswords == 0) {
		LoadConfig(NULL, _T("pass.txt"), config);
	}

	_tprintf(_T("[+] Loaded user list: %i users\r\n"),
		config->credential.nLogins);
	_tprintf(_T("[+] Loaded pass list: %i passwords\r\n\r\n"),
		config->credential.nPasswords);

	if (config->credential.nLogins == 0) {
		_tprintf(_T
			("[-] Unable to perform attack without usernames. Use -L or -l flag\r\n")
			);
		delete config;
		return (NULL);
	}
	if (config->credential.nPasswords == 0) {
		_tprintf(_T
			("[-] Unable to perform attack without passwords. Use -L or -l flag\r\n")
			);
		delete config;
		return (NULL);
	}
	return (config);
}
