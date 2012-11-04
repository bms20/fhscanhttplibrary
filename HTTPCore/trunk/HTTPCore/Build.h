/*
 Copyright (C) 2007 - 2012  fhscan project.
 Andres Tarasco - http://www.tarasco.org/security - http://www.tarlogic.com

 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
 notice, this _sntprintf of conditions and the following disclaimer.
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

/** \file build.h
 * Fast HTTP Auth Scanner - HTTP Engine v1.4.
 * ..
 * \author Andres Tarasco Acuna - http://www.tarasco.org
 */

#ifndef __BUILD_H_
#define __BUILD_H_
#ifndef __TCHAR_H
	#define __TCHAR_H /* force compatibility with codegear includes */
#endif
#ifndef __STDC_ISO_10646__
	#define __STDC_ISO_10646__  200104L
#endif
/****************** GLOBAL FLAGS **********************/
#undef UNICODE
#undef _UNICODE

//#define IPV6


#ifndef UNICODE
//#define _UNICODE
//#define UNICODE
#endif

#ifdef _UNICODE
#define _HTTPWIDECHAR
#endif

#include <stdio.h>
#include <stdlib.h>

#ifndef __linux
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <winnls.h>
// #include <tchar.h>
#ifndef __WIN32__RELEASE__
#define __WIN32__RELEASE__
#endif

#define snprintf _snprintf
#define socklen_t int

# if defined(_MSC_VER)
# ifndef _CRT_SECURE_NO_DEPRECATE
# define _CRT_SECURE_NO_DEPRECATE (1)
# endif
# pragma warning(disable : 4996)
#define stricmp  _stricmp
# else
// #define  _stricmp strcasecmp
#include <winsock2.h> /* Codegear problem with WSADATA definition */
#define _swprintf swprintf

#endif

#else
	#ifndef LINUX
	#define LINUX
	#endif
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>  //pthread
#include <ctype.h> //toupper
// #include <time.h>
#include <sys/timeb.h>
// #include <sys/time.h> //gettimeofday
#include <sys/mman.h>  //mmap
typedef int64_t __int64;
typedef uint64_t __uint64;
#define MAXIMUM_WAIT_OBJECTS 64
#define MAX_PATH 256
// #define __tcsdup strdup
#define BOOL int
#define closesocket close
#define strnicmp strncasecmp
#define  stricmp strcasecmp
#define ioctlsocket ioctl
#define Sleep usleep
#define CRITICAL_SECTION pthread_mutex_t
#define SOCKET int
#ifndef INVALID_SOCKET
#define INVALID_SOCKET  (SOCKET)(~0)
#define FILETIME time_t
#define INVALID_HANDLE_VALUE -1
#define LPVOID void*
#define SOCKET_ERROR -1
#define _snprintf snprintf
#endif
#endif

#ifndef uint64
#define uint64 unsigned long
#define __uint64 unsigned long
#endif

/****************** GLOBAL FLAGS **********************/
#include <time.h>
#ifdef _UNICODE
#include <wchar.h>
#ifndef _TCHAR
typedef wchar_t _TCHAR;
#endif
#define _T(x)           L ## x
#define _tcsdup         _wcsdup
#define _tmain          wmain
#define _tcsstr         wcsstr
#define _tcscmp         wcscmp
#define _tcsnccmp       wcsncmp
#define _tcslen         wcslen
#define _tcsncpy        wcsncpy
#define _tcsncat        wcsncat
#define _sntprintf      _snwprintf
#define _stprintf       _swprintf
#define _tcscpy         wcscpy
#define _tcsncicmp      _wcsnicmp

#define _istspace   iswspace
#define _tcstol     wcstol
#define _tcstok         wcstok
#define _tcschr         wcschr
#define _tstoi      _wtoi
#define _tcscat         wcscat
#define _tcsicmp        _wcsicmp
#define _stscanf        swscanf
#define _istdigit   iswdigit
#define _istspace   iswspace
#define _istxdigit      isxdigit
#define _istalpha   iswalpha
#define _istalnum   iswalnum
#define _totlower   towlower
#define _totupper   towupper
#define _tcsftime   wcsftime
#define _tfopen     _wfopen
#define _tprintf        wprintf
#define _ftprintf       fwprintf
#define _fgetts         fgetws

#else
#ifndef _TCHAR
typedef char _TCHAR;
#endif
#define _T(x)           x
#define _tcsdup         strdup
#define _tmain          main
#define _tcsstr         strstr
#define _tcscmp         strcmp
#define _tcsnccmp       strncmp
#define _tcslen         strlen
#define _tcsncpy        strncpy
#define _tcsncat        strncat
#define _sntprintf      _snprintf
#define _stprintf       sprintf
#define _tcscpy     strcpy
#define _tcsncicmp      strnicmp
#define _istspace   isspace
#define _tcstol     strtol
#define _tcstok         strtok
#define _tcschr         strchr
#define _tstoi      atoi
#define _tcscat     strcat
#define _tcsicmp        stricmp /*borland*/
#define _stscanf        sscanf
#define _istdigit   isdigit
#define _istspace   isspace
#define _istxdigit      isxdigit
#define _istalpha   isalpha
#define _istalnum   isalnum
#define _totlower   tolower
#define _totupper   toupper
#define _tcsftime   strftime
#define _tfopen     fopen
#define _tprintf        printf
#define _ftprintf       fprintf
#define _fgetts         fgets
#endif

#define HTTPCSTR const _TCHAR *
#define HTTPSTR  _TCHAR *
#define HTTPCHAR _TCHAR

#define HTTPCSTR const _TCHAR *
#define HTTPSTR  _TCHAR *
#define HTTPCHAR _TCHAR
#define HTTPCCHAR const _TCHAR

#endif
