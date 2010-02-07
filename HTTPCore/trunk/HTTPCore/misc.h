#ifndef __MISC__FUNCTIONS_H_
#define __MISC__FUNCTIONS_H_

#include "Build.h"


#ifdef __WIN32__RELEASE__
#ifndef __uint64
#define __uint64 unsigned __int64
#endif
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

struct timezone
{
	int  tz_minuteswest; /* minutes W of Greenwich */
	int  tz_dsttime;     /* type of dst correction */
};

int gettimeofday(struct timeval *tv, struct timezone *tz);
HTTPCHAR *__strptime (HTTPCSTR buf, HTTPCSTR format, struct tm *timeptr);
//# if defined(_MSC_VER)


//#endif

#endif

#endif
