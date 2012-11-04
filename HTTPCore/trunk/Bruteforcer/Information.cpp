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

#ifdef __linux
#define WORD unsigned short
#endif

static char *unicodeToString(char *p, size_t len) {
	int i;
	static char buf[16384];

	// assert(len+1 < sizeof buf);

	for (i = 0; i < (signed int)len; ++i) {
		buf[i] = *p & 0x7f;
		p += 2;
	}

	buf[i] = '\0';
	return buf;
}

void Widetochar(char *destination, char *source, int len) {
	int i;
	for (i = 0; i < len / 2; i++) {
		destination[i] = (char) source[i * 2];
		if (destination[i] == '\0')
			return;
	}
	destination[i] = '\0';

}

#define GetUnicodeString(structPtr, header) unicodeToString(((char*)structPtr) + IVAL(&structPtr->header.offset,0) , SVAL(&structPtr->header.len,0)/2)
#define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)
#define IVAL(buf,pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)
#define CVAL(buf,pos) (((unsigned char *)(buf))[pos])
#define PVAL(buf,pos) ((unsigned)CVAL(buf,pos))

void dumpAuthChallenge(tSmbNtlmAuthChallenge *challenge) {

	WORD securityBuffer;
	WORD securityBufferOffsetToData;
	char* ServerName = NULL;
	char* DomainName = NULL;
	char* DnsName = NULL;
	char* FQDNName = NULL;

	WORD domainnamelen;

	WORD tipo;
	WORD len;
	char *offset;

	char *buf = (char*)challenge;
	_tprintf(_T("[+] NTLM Challenge information:\n\n"));
	_tprintf(_T("      Ident = %s\n"), challenge->ident);
	_tprintf(_T("      mType = %d\n"), IVAL(&challenge->msgType, 0));
	if (challenge->msgType != 0x02) {
		_tprintf(_T("[-] NTLM PACKET ERROR. Message Type unexpected\n"));
		return;
	}
	_tprintf(_T("     Domain = %s\n"), GetUnicodeString(challenge, uDomain));
	_tprintf(_T("      Flags = %08x\n"), IVAL(&challenge->flags, 0));

	memcpy((char*)&securityBuffer, buf + 12, 2);
	_tprintf(_T("  SecBuffer = %i\n"), securityBuffer);
	memcpy((char*)&securityBufferOffsetToData, buf + (12 + 4), 2);
	_tprintf(_T("   SBOffset = %i\n"), securityBufferOffsetToData);
	memcpy((char*)&domainnamelen, buf + (12), 2);
	_tprintf(_T("  DomainLen = %i\n"), domainnamelen);

	ServerName = (char*)malloc(domainnamelen / 2 + 1);
	Widetochar(ServerName, buf + (securityBufferOffsetToData), domainnamelen);

	offset = (char*)buf + (securityBufferOffsetToData + domainnamelen);
	free(ServerName);

	do {
		tipo = 0;
		memcpy((char*)&tipo, offset, 2);
		memcpy((char*)&len, offset + 2, 2);
		switch (tipo) {
		case 0x01:
			ServerName = (char*)malloc(len / 2 + 1);
			Widetochar(ServerName, offset + 4, len);
			_tprintf(_T(" ServerName = %s\n"), ServerName);
			free(ServerName);
			break;
		case 0x02:
			DomainName = (char*)malloc(len / 2 + 1);
			Widetochar(DomainName, offset + 4, len);
			_tprintf(_T(" DomainName = %s\n"), DomainName);
			free(DomainName);
			break;
		case 0x03:
			FQDNName = (char*)malloc(len / 2 + 1);
			Widetochar(FQDNName, offset + 4, len);
			_tprintf(_T("   FQDNName = %s\n"), FQDNName);
			free(FQDNName);
			break;
		case 0x04:
			DnsName = (char*)malloc(len / 2 + 1);
			Widetochar(DnsName, offset + 4, len);
			_tprintf(_T("    DnsName = %s\n"), DnsName);
			free(DnsName);
			break;
		}
		offset += 2 + 2 + len;
	}
	while (tipo != 0);
}

int CBInformacion(int cbType, class HTTPAPI *api, HTTPHANDLE HTTPHandle,
	HTTPRequest* request, HTTPResponse* response) {
	if (response) {
		HTTPCHAR *Header = response->GetHeaderValue(_T("WWW-Authenticate:"), 0);
		if (Header) {
			if (_tcslen(Header) > 4) {
				encoders *encoder = new encoders;
#ifdef _UNICODE
				tSmbNtlmAuthChallenge *challenge =
					(tSmbNtlmAuthChallenge*)encoder->decodebase64W(NULL,
					Header + 5);
#else
				tSmbNtlmAuthChallenge *challenge =
					(tSmbNtlmAuthChallenge*)encoder->decodebase64A(NULL,
					Header + 5);
#endif
				if (challenge) {
					dumpAuthChallenge(challenge);
					free(challenge);
				}
				delete encoder;
			}
			free(Header);
		}
	}
	return (CBRET_STATUS_NEXT_CB_CONTINUE);
}

int GetInformation(HTTPAPI *api, HTTPHANDLE HTTPHandle, HTTPCCHAR *host,
	int port, HTTPCCHAR *uri, int SSL, HTTPCCHAR *Method,
	HTTPCCHAR *AdditionalHeaders) {

	int ret = NO_AUTH;
	if (*AdditionalHeaders) {
		api->SetHTTPConfig(HTTPHandle, ConfigAdditionalHeader,
		AdditionalHeaders);
	}
	HTTPSession* data = api->SendHttpRequest(HTTPHandle, Method, uri);
	if (data) {
		_tprintf(_T("[+] Remote Web server : %s\r\n"), data->server);
		if (data->status != 401) {
			_tprintf(_T("[-] The remote resource does not requiere auth\r\n"));
			delete data;
			return (0);
		}
		int i = 0;
		HTTPCHAR *auth;
		const HTTPCHAR AuthNeeded[] = _T("WWW-Authenticate:");

		do {
			auth = data->response->GetHeaderValue(AuthNeeded, i++);
			if (auth) {
				if (_tcsncicmp(auth, _T("basic"), 5) == 0) {
					if (!(ret & BASIC_AUTH)) {
						_tprintf(_T
							("[+] The remote webserver supports Basic Auth.\r\n"
							));
						_tprintf(_T("[+] %s\n"), auth);
						ret += BASIC_AUTH;
					}
				}
				else if (_tcsncicmp(auth, _T("digest"), 6) == 0) {
					if (!(ret & DIGEST_AUTH)) {
						_tprintf(_T
							("[+] The remote webserver supports digest Auth.\n")
							);
						_tprintf(_T("[+] %s\n"), auth);
						ret += DIGEST_AUTH;
					}
				}
				else if (_tcsncicmp(auth, _T("ntlm"), 4) == 0) {
					if (!(ret & NTLM_AUTH)) {
						_tprintf(_T
							("[+] The remote webserver supports NTLM Auth\n"));
						ret += NTLM_AUTH;
					}
				}
				else if (_tcsncicmp(auth, _T("Negotiate"), 9) == 0) {
					if (!(ret & NEGOTIATE_AUTH)) {
						_tprintf(_T
							("[+] The remote webserver supports NEGOTIATE Auth\n")
							);
						ret += NEGOTIATE_AUTH;
					}
				}
				else {
					if (!(ret & UNKNOWN_AUTH)) {
						_tprintf(_T
							("[+] The remote webserver supports UNKNOWN Auth: %s\n")
							, auth);
						ret += UNKNOWN_AUTH;
					}
				}
				free(auth);
			}
		}
		while (auth);
		delete data;

		if (ret == NO_AUTH) {
			_tprintf(_T("[+] The remote webserver does not requiere Auth\n"));
			return (0);
		}

		if ((ret & NTLM_AUTH) || (ret & NEGOTIATE_AUTH)) {
			api->RegisterHTTPCallBack(CBTYPE_CLIENT_RESPONSE,
				(HTTP_IO_REQUEST_CALLBACK)CBInformacion, _T("NTLM Info"));
			HTTPSession* data = api->SendHttpRequest(HTTPHandle, Method, uri,
				_T(""), _T("Tarwi-Auth-Test-Username"),
				_T("Tarwi-Auth-Test-Password"));
			api->RemoveHTTPCallBack(CBTYPE_CLIENT_RESPONSE,
				(HTTP_IO_REQUEST_CALLBACK)CBInformacion);
			if (data) {
				delete(data);
			}
		}
	}
	else {
		_tprintf(_T("[-] Unable to connect to the remote HTTP%c server\r\n"),
			SSL ? _T('s') : _T(' '));
		return (0);
	}

	return (ret);
}
