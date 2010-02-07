#include "misc.h"
#include <time.h>
/*
 ****** Misc Functions for HTTP Engine *****
 * Like time functions

*/

#ifdef __WIN32__RELEASE__
#include <windows.h>
/*******************************************************************************************************/

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	FILETIME ft;
	unsigned __int64 tmpres = 0;
	static int tzflag;

	if (NULL != tv)
	{
		GetSystemTimeAsFileTime(&ft);

		tmpres |= ft.dwHighDateTime;
		tmpres <<= 32;
		tmpres |= ft.dwLowDateTime;

		/*converting file time to unix epoch*/
		tmpres /= 10;  /*convert into microseconds*/
		tmpres -= DELTA_EPOCH_IN_MICROSECS;
		tv->tv_sec = (long)(tmpres / 1000000UL);
		tv->tv_usec = (long)(tmpres % 1000000UL);
	}

	if (NULL != tz)
	{
		if (!tzflag)
		{
			_tzset();
			tzflag++;
		}
		tz->tz_minuteswest = _timezone / 60;
		tz->tz_dsttime = _daylight;
	}

	return 0;
}
//#if defined(_MSC_VER)
#ifdef __WIN32__RELEASE__

/*
 * Copyright (c) 1999 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "Build.h"
#include <ctype.h>
//#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "roken.h"

//RCSID("$Id: strptime.c,v 1.4 2004/08/07 13:33:34 tol Exp $");

static HTTPCSTR abb_weekdays[] = {
    _T("Sun"),
    _T("Mon"),
    _T("Tue"),
    _T("Wed"),
    _T("Thu"),
    _T("Fri"),
    _T("Sat"),
    NULL
};

static HTTPCSTR full_weekdays[] = {
    _T("Sunday"),
    _T("Monday"),
    _T("Tuesday"),
    _T("Wednesday"),
    _T("Thursday"),
    _T("Friday"),
    _T("Saturday"),
    NULL
};

static HTTPCSTR abb_month[] = {
    _T("Jan"),
    _T("Feb"),
    _T("Mar"),
    _T("Apr"),
    _T("May"),
    _T("Jun"),
    _T("Jul"),
    _T("Aug"),
    _T("Sep"),
    _T("Oct"),
    _T("Nov"),
    _T("Dec"),
    NULL
};

static HTTPCSTR full_month[] = {
    _T("January"),
    _T("February"),
    _T("Mars"),
    _T("April"),
    _T("May"),
    _T("June"),
    _T("July"),
    _T("August"),
    _T("September"),
    _T("October"),
    _T("November"),
    _T("December"),
    NULL,
};

static HTTPCSTR ampm[] = {
    _T("am"),
    _T("pm"),
    NULL
};

/*
 * Try to match `*buf' to one of the strings in `strs'.  Return the
 * index of the matching string (or -1 if none).  Also advance buf.
 */

static int
match_string (HTTPCSTR *buf, HTTPCSTR *strs)
{
    int i = 0;

    for (i = 0; strs[i] != NULL; ++i) {
        int len = (int)_tcslen (strs[i]);

        if (_tcsncicmp (*buf, strs[i], len) == 0) {
            *buf += len;
            return i;
        }
    }
    return -1;
}

/*
 * tm_year is relative this year */

const int tm_year_base = 1900;

/*
 * Return TRUE iff `year' was a leap year.
 */

static int is_leap_year (int year)
{
    return (year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0);
}

/*
 * Return the weekday [0,6] (0 = Sunday) of the first day of `year'
 */

static int first_day (int year)
{
    int ret = 4;

    for (; year > 1970; --year)
        ret = (ret + 365 + is_leap_year (year) ? 1 : 0) % 7;
    return ret;
}

/*
 * Set `timeptr' given `wnum' (week number [0, 53])
 */

static void set_week_number_sun (struct tm *timeptr, int wnum)
{
    int fday = first_day (timeptr->tm_year + tm_year_base);

    timeptr->tm_yday = wnum * 7 + timeptr->tm_wday - fday;
    if (timeptr->tm_yday < 0) {
        timeptr->tm_wday = fday;
        timeptr->tm_yday = 0;
    }
}

/*
 * Set `timeptr' given `wnum' (week number [0, 53])
 */

static void set_week_number_mon (struct tm *timeptr, int wnum)
{
    int fday = (first_day (timeptr->tm_year + tm_year_base) + 6) % 7;

    timeptr->tm_yday = wnum * 7 + (timeptr->tm_wday + 6) % 7 - fday;
    if (timeptr->tm_yday < 0) {
        timeptr->tm_wday = (fday + 1) % 7;
        timeptr->tm_yday = 0;
    }
}

/*
 * Set `timeptr' given `wnum' (week number [0, 53])
 */

static void set_week_number_mon4 (struct tm *timeptr, int wnum)
{
    int fday = (first_day (timeptr->tm_year + tm_year_base) + 6) % 7;
    int offset = 0;

    if (fday < 4)
        offset += 7;

    timeptr->tm_yday = offset + (wnum - 1) * 7 + timeptr->tm_wday - fday;
    if (timeptr->tm_yday < 0) {
        timeptr->tm_wday = fday;
        timeptr->tm_yday = 0;
    }
}

/*
 *
 */

HTTPCHAR *__strptime (HTTPCSTR buf, HTTPCSTR format, struct tm *timeptr)
{
    HTTPCHAR c;

    for (; (c = *format) != _T('\0'); ++format) {
        HTTPCHAR *s;
        int ret;

        if (isspace (c)) {
            while (isspace (*buf))
                ++buf;
        } else if (c == _T('%') && format[1] != _T('\0')) {
            c = *++format;
            if (c == _T('E') || c == _T('O'))
                c = *++format;
            switch (c) {
            case _T('A') :
                ret = match_string (&buf, full_weekdays);
                if (ret < 0)
                    return NULL;
                timeptr->tm_wday = ret;
                break;
            case _T('a') :
                ret = match_string (&buf, abb_weekdays);
                if (ret < 0)
                    return NULL;
                timeptr->tm_wday = ret;
                break;
            case _T('B') :
                ret = match_string (&buf, full_month);
                if (ret < 0)
                    return NULL;
                timeptr->tm_mon = ret;
                break;
            case _T('b') :
            case _T('h') :
                ret = match_string (&buf, abb_month);
                if (ret < 0)
                    return NULL;
                timeptr->tm_mon = ret;
                break;
            case _T('C') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                timeptr->tm_year = (ret * 100) - tm_year_base;
                buf = s;
                break;
            case _T('c') :
                abort ();
            case _T('D') :          /* %m/%d/%y */
                s = __strptime (buf, _T("%m/%d/%y"), timeptr);
                if (s == NULL)
                    return NULL;
                buf = s;
                break;
            case _T('d') :
            case _T('e') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                timeptr->tm_mday = ret;
                buf = s;
                break;
            case _T('H') :
            case _T('k') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                timeptr->tm_hour = ret;
                buf = s;
                break;
            case _T('I') :
            case _T('l') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                if (ret == 12)
                    timeptr->tm_hour = 0;
                else
                    timeptr->tm_hour = ret;
                buf = s;
                break;
            case _T('j') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                timeptr->tm_yday = ret - 1;
                buf = s;
                break;
            case _T('m') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                timeptr->tm_mon = ret - 1;
                buf = s;
                break;
            case _T('M') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                timeptr->tm_min = ret;
                buf = s;
                break;
            case _T('n') :
                if (*buf == _T('\n'))
                    ++buf;
                else
                    return NULL;
                break;
            case _T('p') :
                ret = match_string (&buf, ampm);
                if (ret < 0)
                    return NULL;
                if (timeptr->tm_hour == 0) {
                    if (ret == 1)
                        timeptr->tm_hour = 12;
                } else
                    timeptr->tm_hour += 12;
                break;
            case _T('r') :          /* %I:%M:%S %p */
                s = __strptime (buf, _T("%I:%M:%S %p"), timeptr);
                if (s == NULL)
                    return NULL;
                buf = s;
                break;
            case _T('R') :          /* %H:%M */
                s = __strptime (buf, _T("%H:%M"), timeptr);
                if (s == NULL)
                    return NULL;
                buf = s;
                break;
            case _T('S') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                timeptr->tm_sec = ret;
                buf = s;
                break;
            case _T('t') :
                if (*buf == _T('\t'))
                    ++buf;
                else
                    return NULL;
                break;
            case _T('T') :          /* %H:%M:%S */
            case _T('X') :
                s = __strptime (buf, _T("%H:%M:%S"), timeptr);
                if (s == NULL)
                    return NULL;
                buf = s;
                break;
            case _T('u') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                timeptr->tm_wday = ret - 1;
                buf = s;
                break;
            case _T('w') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                timeptr->tm_wday = ret;
                buf = s;
                break;
            case _T('U') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                set_week_number_sun (timeptr, ret);
                buf = s;
                break;
            case _T('V') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                set_week_number_mon4 (timeptr, ret);
                buf = s;
                break;
            case _T('W') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                set_week_number_mon (timeptr, ret);
                buf = s;
                break;
            case _T('x') :
                s = __strptime (buf, _T("%Y:%m:%d"), timeptr);
                if (s == NULL)
                    return NULL;
                buf = s;
                break;
            case _T('y') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                if (ret < 70)
                    timeptr->tm_year = 100 + ret;
                else
                    timeptr->tm_year = ret;
                buf = s;
                break;
            case _T('Y') :
                ret = _tcstol (buf, &s, 10);
                if (s == buf)
                    return NULL;
                timeptr->tm_year = ret - tm_year_base;
                buf = s;
                break;
            case _T('Z') :
                abort ();
            case _T('\0') :
                --format;
                /* FALLTHROUGH */
            case _T('%') :
                if (*buf == _T('%'))
                    ++buf;
                else
                    return NULL;
                break;
            default :
                if (*buf == _T('%') || *++buf == c)
                    ++buf;
                else
                    return NULL;
                break;
            }
        } else {
            if (*buf == c)
                ++buf;
            else
                return NULL;
        }
    }
    return (HTTPCHAR *)buf;
}
#endif
#endif


