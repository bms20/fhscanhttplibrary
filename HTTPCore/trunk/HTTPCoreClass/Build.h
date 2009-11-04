#ifndef __BUILD_H_
#define __BUILD_H_

/****************** GLOBAL FLAGS **********************/
#ifndef _HTTPWIDECHAR
	#define _HTTPWIDECHAR
#endif
#undef  _HTTPWIDECHAR

#ifdef _HTTPWIDECHAR
	//#define _CXML(c) L ## c
	#define HTTPCSTR const wchar_t *
	#define HTTPSTR  wchar_t *
	#define HTTPCHAR wchar_t
#else
	//#define _CXML(c) c
	#define HTTPCSTR const char *
	#define HTTPSTR  char *
	#define HTTPCHAR char
#endif

#ifndef LINUX

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
//  #define  _stricmp strcasecmp
#include <winsock2.h> /* Codegear problem with WSADATA definition */
#endif

#else

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>  //pthread
#include <ctype.h> //toupper
#include <time.h>
#include <sys/timeb.h>
#include <sys/time.h> //gettimeofday
#include <sys/mman.h>  //mmap
typedef int64_t __int64;
typedef uint64_t __uint64;
#define MAXIMUM_WAIT_OBJECTS 64
#define MAX_PATH 256
#define _strdup strdup
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
#endif
#endif
/****************** GLOBAL FLAGS **********************/

#endif


