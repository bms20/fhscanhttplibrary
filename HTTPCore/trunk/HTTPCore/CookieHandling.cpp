/*
 Copyright (C) 2007 - 2012  fhscan project.
 Andres Tarasco - http://www.tarasco.org/security - http://www.tarlogic.com

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
/** \file CookieHandling.cpp
 * Fast HTTP Auth Scanner - HTTP Engine v1.4
 * This include file contains functions needed to Handle Cookies From the HTTP API.
 * \author Andres Tarasco Acuna - http://www.tarasco.org
 */
#include "Build.h"
#include "CookieHandling.h"
#include "HtmlParser.h"
#include "misc.h"
#include <string.h>
// #include <time.h>

Cookie::Cookie() {
	lpCookieName = NULL;
	lpCookieValue = NULL;
	expire = (time_t) - 1;
	path = NULL;
	domain = NULL;
	secure = 0;
	httponly = 0;
}

Cookie::Cookie(HTTPCHAR *cName, HTTPCHAR *cValue, time_t cExpire,
	HTTPCHAR *cPath, HTTPCHAR *cDomain, int cSecure, int cHttponly) {
	lpCookieName = _tcsdup(cName);
	lpCookieValue = _tcsdup(cValue);
	expire = cExpire;
	path = _tcsdup(cPath);
	domain = _tcsdup(cDomain);
	secure = cSecure;
	httponly = cHttponly;
}

void Cookie::SetValue(HTTPCHAR *cValue) {
	if (lpCookieValue)
		free(lpCookieValue);
	lpCookieValue = _tcsdup(cValue);
}

void Cookie::SetDate(time_t cExpire) {
	expire = cExpire;
}

size_t Cookie::path_matches(HTTPCSTR RequestedPath) {
	size_t len = _tcslen(path);
	if (_tcsnccmp(RequestedPath, path, len))
		/* FULL_PATH doesn't begin with PREFIX. */
			return 0;

	/* Length of PREFIX determines the quality of the match. */
	return len;
}

int Cookie::MatchCookie(HTTPCHAR *lppath, HTTPCHAR *lpdomain,
	HTTPCHAR *CookieName, int securevalue) {
	/*
	 int ret1=       (_tcscmp(lpCookieName, CookieName) == 0);
	 int ret2 =       (_tcscmp(lppath, path) == 0);
	 int ret3 =       (securevalue == secure);
	 int ret4 =      (_tcscmp(lpdomain,lpdomain) == 0);
	 */

	return ((_tcscmp(lpCookieName, CookieName) == 0) && (_tcscmp(lppath,
		path) == 0) && (securevalue == secure) && (_tcscmp(lpdomain,
		lpdomain) == 0));
}

Cookie::~Cookie() {
	if (lpCookieName) {
		free(lpCookieName);
		lpCookieName = NULL;
	}
	if (lpCookieValue) {
		free(lpCookieValue);
		lpCookieValue = NULL;
	}
	if (path) {
		free(path);
		path = NULL;
	}
	if (domain) {
		free(domain);
		domain = NULL;
	}
	secure = 0;
	httponly = 0;
}
//-----------------------------------------------------------------------------
 CookieStatus::CookieStatus()
 {
 DomainList = new bTree(_T("http://"));
 nDomains = 0;
 }

 CookieStatus::~CookieStatus()
 {
 for(int i=0;i<DomainList->GetCount();i++)
 {
/* Extract nodes for each domain registered at the DomainList btree */
TreeNode *node = DomainList->GetTreeNodeItemID(i);
if (node) {
	/* Get the Cookie List associated with each domain */
	struct CookieList *List = (struct CookieList*)node->GetData();
	if (List) {
		if (List->nCookies) {
			for (int j = 0; j < List->nCookies; j++) {
				delete List->CookieElement[j];
			}
			free(List->CookieElement);
			List->CookieElement = NULL;
		}
		free(List);
	}
	node->SetData(NULL);
}
} delete DomainList;
}

/* Ripped from wget */
int CookieStatus::numeric_address_p(HTTPCSTR addr) {
HTTPCSTR p = addr;

REQUIRE_DIGITS(p); /* A */
REQUIRE_DOT(p); /* . */
REQUIRE_DIGITS(p); /* B */
REQUIRE_DOT(p); /* . */
REQUIRE_DIGITS(p); /* C */
REQUIRE_DOT(p); /* . */
REQUIRE_DIGITS(p); /* D */

if (*p != '\0')
return 0;
return 1;
}

/* Check whether COOKIE_DOMAIN is an appropriate domain for HOST.
 This check is compliant with rfc2109. */

int CookieStatus::check_domain_match(HTTPCSTR cookie_domain, HTTPCSTR host) {
size_t headlen;
HTTPCSTR tail;
/* Numeric address requires exact match.  It also requires HOST to
 be an IP address.  I suppose we *could* resolve HOST with
 store_hostaddress (it would hit the hash table), but rfc2109
 doesn't require it, and it doesn't seem very useful, so we
 don't. */
if (numeric_address_p(cookie_domain))
return !_tcscmp(cookie_domain, host);

/* The domain must contain at least one embedded dot. */
HTTPCSTR rest = cookie_domain;
size_t len = _tcslen(rest);
if (*rest == _T('.'))
++rest, --len; /* ignore first dot */
if (len <= 0)
return 0;
if (rest[len - 1] == _T('.'))
--len; /* ignore last dot */
if (!memchr(rest, '.', len)) /* No dots. */
	return 0;

/* For the sake of efficiency, check for exact match first. */
if (!_tcsicmp(cookie_domain, host))
return 1;

/* In rfc2109 terminology, HOST needs domain-match COOKIE_DOMAIN.
 This means that COOKIE_DOMAIN needs to start with `.' and be an
 FQDN, and that HOST must end with COOKIE_DOMAIN. */
if (*cookie_domain != '.')
return 0;

/* Two proceed, we need to examine two parts of HOST: its head and
 its tail.  Head and tail are defined in terms of the length of
 the domain, like this:

 HHHHTTTTTTTTTTTTTTT  <- host
 DDDDDDDDDDDDDDD  <- domain

 That is, "head" is the part of the host before (dlen - hlen), and
 "tail" is what follows.

 For the domain to match, two conditions need to be true:

 1. Tail must equal DOMAIN.
 2. Head must not contain an embedded dot. */

headlen = _tcslen(host) - _tcslen(cookie_domain);

if (headlen <= 0)
	/* DOMAIN must be a proper subset of HOST. */
	return 0;
tail = host + headlen;

/* (1) */
if (_tcsicmp(tail, cookie_domain))
return 0;

/* Test (2) is not part of the "domain-match" itself, but is
 recommended by rfc2109 for reasons of privacy. */
/* (2) */
if (memchr(host, '.', headlen))
return 0;
return 1;
}

BOOL CookieStatus::cookie_expired(time_t CookieExpireTime) {
return ((CookieExpireTime != 0) && (CookieExpireTime < time(NULL)));
}

/*
 Examina un array CoookieList y verifica si ya existe la cookie
 */
int CookieStatus::CookieAlreadyExist(struct CookieList *List, HTTPCHAR *path,
	HTTPCHAR *domain, HTTPCHAR *name, int secure) {
int ret;
for (int i = 0; i < List->nCookies; i++) {
ret = List->CookieElement[i]->MatchCookie(path, domain, name, secure);
if (ret == 1)
	return (1);
}
return (-1);

}

HTTPCHAR *CookieStatus::ReturnCookieHeaderFor(HTTPCSTR lpDomain, HTTPCSTR path,
	int CookieOverSSL) {

/* Locate Which node Name should be retrieved */
HTTPCSTR DomainNameTreeNode = NULL;
if (numeric_address_p(lpDomain)) {
DomainNameTreeNode = lpDomain;
}
else {
size_t len = _tcslen(lpDomain) - 1;
int n = 0;
while (len > 0) {
	if (lpDomain[len] == '.')
		n++;
	if (n == 2) {
		DomainNameTreeNode = lpDomain + len + 1;
		break;
	}
	len--;
}
if (!DomainNameTreeNode)
	DomainNameTreeNode = lpDomain;
}

TreeNode *node = DomainList->TreeExistItem(DomainNameTreeNode);
if (node) {
struct CookieList *List = (struct CookieList*)node->GetData();
if (List) {
	HTTPCHAR *ServerCookie = NULL;
	time_t CurrentTime = time(NULL);
	struct tm *test = gmtime(&CurrentTime);
	CurrentTime = mktime(test);
	for (int i = 0; i < List->nCookies; i++) {
		/*
		 int ret1 =List->CookieElement[i]->path_matches(path);
		 int ret2 =    (List->CookieElement[i]->GetDate() == 0);
		 int ret3 = List->CookieElement[i]->GetDate() >= CurrentTime;
		 int ret4 = check_domain_match (List->CookieElement[i]->GetCookieDomain(), lpDomain);
		 int ret5 =  !List->CookieElement[i]->IsSecure();
		 int ret6 =  CookieOverSSL;
		 */
		if ((List->CookieElement[i]->path_matches(path)) && /* Match path */
			((List->CookieElement[i]->GetDate() == 0) ||
			(List->CookieElement[i]->GetDate() >= CurrentTime))
			&& /* Match time */ (check_domain_match
			(List->CookieElement[i]->GetCookieDomain(), lpDomain))
			&& /* Match Domain */ ((!List->CookieElement[i]->IsSecure()) ||
			CookieOverSSL)) /* Match SSL Cookie status */ {
			// printf("Sacando Cookie %i\n",i);
			if (!ServerCookie) {
				ServerCookie =
					(HTTPCHAR*)malloc
					((_tcslen(List->CookieElement[i]->GetCookieName()) +
					_tcslen(List->CookieElement[i]->GetCookieValue()) + 1 + 1)
					*sizeof(HTTPCHAR));
				if (ServerCookie) {
					_stprintf(ServerCookie, _T("%s=%s"),
						List->CookieElement[i]->GetCookieName(),
						List->CookieElement[i]->GetCookieValue());
				}
			}
			else {
				ServerCookie = (HTTPCHAR*)realloc(ServerCookie,
					(_tcslen(ServerCookie) + 2 +
					_tcslen(List->CookieElement[i]->GetCookieName()) +
					_tcslen(List->CookieElement[i]->GetCookieValue()) + 1 + 1)
					*sizeof(HTTPCHAR));
				_tcscat(ServerCookie, _T("; "));
				_tcscat(ServerCookie, List->CookieElement[i]->GetCookieName());
				_tcscat(ServerCookie, _T("="));
				_tcscat(ServerCookie, List->CookieElement[i]->GetCookieValue());

			}
		}
		else {
			// printf("Ignored Cookie %s  for %s\n",List->CookieElement[i]->GetCookieName(),path);
		}
	}
	// if (ServerCookie) printf("Generado: %s\n",ServerCookie);
	return (ServerCookie);
}
}
return (NULL);
}

int CookieStatus::ParseCookieData(HTTPCHAR *lpCookieData, HTTPCSTR lpPath,
	HTTPCSTR lpDomain) {
int nvalues = 0;
HTTPCHAR **name = NULL;
HTTPCHAR **value = NULL;
time_t expire = (time_t)0;
time_t CurrentTime = 0;

// DomainList->SetTreeName(lpDomain);
HTTPCHAR *path = NULL;
HTTPCHAR *domain = NULL;
BOOL secure = 0;
BOOL httponly = 0;
int err = 0;
HTTPCHAR *start, *end;
int deletecookie = 0;

HTTPCSTR DomainNameTreeNode = NULL;
// First Of all we need to extract the domain name from the audited Host:
if (numeric_address_p(lpDomain)) {
DomainNameTreeNode = lpDomain;
}
else {
size_t len = _tcslen(lpDomain) - 1;
int n = 0;
while (len > 0) {
	if (lpDomain[len] == '.')
		n++;
	if (n == 2) {
		DomainNameTreeNode = lpDomain + len + 1;
		break;
	}
	len--;
}
if (!DomainNameTreeNode)
	DomainNameTreeNode = lpDomain;
}

HTTPCHAR *p = _tcstok(lpCookieData, _T(";"));
while ((p) && (!err)) {
GetDataWithoutSpaces(p);
start = p;
end = _tcschr(p, _T('='));
if (end) {
	*end = 0;
	end++;
}
if (end) {
	if IS_PATH(start) {
		path = _tcsdup(end);
	}
	else if IS_DOMAIN(start) {
		int ret = check_domain_match(end, lpDomain);
		if (ret) {
			domain = _tcsdup(end);
		}
		else {
			err = 1;
			// printf("- Error.%s not added as cookie domain. Current Domain is %s\n",end,DomainNameTreeNode);

		}
	}
	else if IS_MAXAGE(start) {
		time_t maxage = -1;
		_stscanf(end, _T("%i"), (int*)&maxage);
		if (maxage != -1) {
			if (maxage == 0) {
				deletecookie = 1;

			}
			else {
				CurrentTime = time(NULL);
				struct tm *test = gmtime(&CurrentTime);
				CurrentTime = mktime(test);
				expire = CurrentTime + maxage;
				// printf("Fecha Expiración: %s\n",ctime(&expire));
			}
		}
	}
	else if IS_EXPIRES(start) {
		expire = ExtractDate(end);
		if (expire == (time_t) - 1) {
			// TODO: Meter soporte de time64
			deletecookie = 1;
		}
		else {
			CurrentTime = time(NULL);
			struct tm *test = gmtime(&CurrentTime);
			CurrentTime = mktime(test);
			if (CurrentTime > expire)
				deletecookie = 1;
		}
		if (deletecookie) {
#ifdef _DBG_
			_tprintf(_T("OLD DATE: %s\n"), end);
#endif

		}
	}
	else if IS_VERSION(start) {
		/* Do nothing with this flag */

	}
	else {
		if (nvalues == 0) {
			name = (HTTPCHAR * *) malloc(sizeof(HTTPCHAR*));
			value = (HTTPCHAR * *) malloc(sizeof(HTTPCHAR*));
		}
		else {
			name = (HTTPCHAR * *)realloc(name, (nvalues + 1)*sizeof(HTTPCHAR*));
			value = (HTTPCHAR * *)realloc(value,
				(nvalues + 1)*sizeof(HTTPCHAR*));
		}
		if (name)
			name[nvalues] = _tcsdup(start);
		if (value)
			value[nvalues] = _tcsdup(end);
		nvalues++;
	}
}
else {
	if (IS_HTTPONLY(start) || IS_HTTPONLY2(start)) {
		httponly = 1;
	}
	else if IS_SECURE(start) {
		secure = 1;
	}
	else {
#ifdef _DBG_
		_tprintf(_T("Ignored Unknown Cookie Flag: %s\n"), start);
#endif
	}
}
p = _tcstok(NULL, _T(";"));

}

if (!err) {

lock.LockMutex();
TreeNode *node = DomainList->TreeExistItem(DomainNameTreeNode);
if (!node) {
	node = DomainList->TreeInsert(DomainNameTreeNode);
	nDomains++;
}
struct CookieList *List = (struct CookieList*)node->GetData();
if (!path)
	path = _tcsdup(lpPath);
if (!domain)
	domain = _tcsdup(lpDomain);
if (deletecookie) {
	/* Delete previous stored cookies */
	// printf("- Old Cookie ( %i secs).. Eliminando Cookie \n",CurrentTime - expire);
	if (List) {
		for (int i = 0; i < nvalues; i++) {
			RemoveCookieFromList(List, path, name[i], domain);
		}
	}
}
else {
	/* Insert new Cookies */
	if (!List) {
		List = (struct CookieList*)malloc(sizeof(struct CookieList));
		if (List) {
			// List->lock = new  Threading;
			List->nCookies = 0;
			node->SetData(List);
		}
	}
	for (int i = 0; i < nvalues; i++) {

		int ret = CookieAlreadyExist(List, path, domain, name[i], secure);
		if (ret >= 0) {
			// printf("- IGNORED - Cookie already exists %s=%s en %s\n",name[i],value[i],path);
			/* Modify Cookie */
			List->CookieElement[ret]->SetValue(value[i]);
			List->CookieElement[ret]->SetDate(expire);

		}
		else {
			// printf("- **ADDED %s=%s en %s\n",name[i],value[i],path);
			/* Insert New Cookie */
			if (!List->nCookies) {
				List->CookieElement = (Cookie * *)malloc(sizeof(Cookie*));
			}
			else {
				List->CookieElement = (Cookie * *)realloc(List->CookieElement,
					sizeof(Cookie*)*(List->nCookies + 1));
			}
			if (List->CookieElement) {
				List->CookieElement[List->nCookies] =
					new Cookie(name[i], value[i], expire, path, domain, secure,
					httponly);
				// _tprintf(_T("Insertada la Cookie%i %s=%s en %s (%s)\n"),List->nCookies,name[i],value[i],path,domain);
				List->nCookies++;
			}

		}
	}
}
lock.UnLockMutex();
}
if (name) {
for (int i = 0; i < nvalues; i++) {
	free(name[i]);
}
free(name);
}
if (value) {
for (int i = 0; i < nvalues; i++) {
	free(value[i]);
}
free(value);
}
if (path) {
free(path);
}
if (domain) {
free(domain);
}

return (0);

}

int CookieStatus::RemoveCookieFromList(struct CookieList *List, HTTPCHAR *path,
	HTTPCHAR *name, HTTPCHAR *lpDomain) {
for (int i = 0; i < List->nCookies; i++) {
if ((List->CookieElement[i]->path_matches(path)) && /* Match path */
	(_tcscmp(List->CookieElement[i]->GetCookieName(), name) == 0)
	&& /* Match Cookie Name */ (_tcscmp(List->CookieElement[i]->GetCookieDomain
	(), lpDomain) == 0)) /* Match target domain */ {
	delete List->CookieElement[i];
	List->CookieElement[i] = List->CookieElement[List->nCookies - 1];
	List->nCookies--;
}
}
return (1);
}
/*
 void CookieStatus::InsertCookieToList(struct CookieList *List,char *path, char *name, char *value, int secure, int HttpOnly)
 {
 }
 */

time_t CookieStatus::ExtractDate(HTTPCHAR *lpdate) {
struct tm expirestm;

if (__strptime(lpdate, COOKIETIMEFORMAT, &expirestm)) {
time_t ret = mktime(&expirestm);
if (ret != -1) {
	return (ret);
}
/* Avoid error when using _mktime32 with future dates > jan 19 2038 */
/* We hack date instead of using _mktime64 for now */
__strptime(_T("Wed, 1-Jan-2038 00:00:00 GMT"), COOKIETIMEFORMAT, &expirestm);
return (mktime(&expirestm));

}
else if (__strptime(lpdate, COOKIETIMEFORMAT2, &expirestm)) {
expirestm.tm_year += 1900;
return (mktime(&expirestm));
}
// printf("Invalid data\n");
return (-1);

}

//-----------------------------------------------------------------------------
