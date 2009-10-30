#ifdef _ZLIB_SUPPORT_
#ifndef _ENCODING_DEFLATE_
#define _ENCODING_DEFLATE_

#include "../CallBacks.h"
#ifdef __WIN32__RELEASE__
	#include "../../Includes/Zlib/zlib.h"
	#include "../../Includes/Zlib/zconf.h"
	typedef int (*INFLATE_FUNC)(z_streamp ,int);
	typedef int (*INFLATEINIT_FUNC)(z_streamp,const char *, int);
	typedef int (*INFLATEEND_FUNC)(z_streamp);
	typedef int (*INFLATEINIT2_FUNC)(z_streamp,int,const char*,int);
	extern INFLATE_FUNC				INFLATE;
	extern INFLATEINIT_FUNC			INFLATEINIT;
	extern INFLATEEND_FUNC			INFLATEEND;
	extern INFLATEINIT2_FUNC		INFLATEINIT2;

#else
	#include <zlib.h>
	#include <zconf.h>
	#define INFLATE					inflate
	#define INFLATEINIT				inflateInit_
	#define INFLATEEND				inflateEnd
	#define INFLATEINIT2			inflateInit2_
#endif

#define NORMAL_DATA	 0
#define GZIP_DATA 	 1
#define DEFLATE_DATA 2

int CBDeflate(int cbType,class HTTPAPI *api,HTTPHANDLE HTTPHandle,PHTTP_DATA request,PHTTP_DATA response);

#endif
#endif


