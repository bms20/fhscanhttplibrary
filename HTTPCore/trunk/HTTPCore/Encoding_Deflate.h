#ifdef _ZLIB_SUPPORT_
#ifndef _ENCODING_DEFLATE_
#define _ENCODING_DEFLATE_

#include "CallBacks.h"
#ifdef __WIN32__RELEASE__
	#include "zlib.h"
	#include "zconf.h"
	typedef int (*INFLATE_FUNC)(z_streamp, int);
	typedef int (*INFLATEINIT_FUNC)(z_streamp, char* , int);
	typedef int (*INFLATEEND_FUNC)(z_streamp );
	typedef int (*INFLATEINIT2_FUNC)(z_streamp ,int, const char*,int);
	typedef int (*INFLATESETDICTIONARY_FUNC) (z_streamp,const Bytef*, int);

	typedef int (*DEFLATEINIT_FUNC) (z_streamp,int, char*, int);
	typedef int (*DEFLATE_FUNC) (z_streamp,int);
	typedef int (*DEFLATEEND_FUNC)(z_streamp );
	typedef int (*DEFLATESETDICTIONARY_FUNC) (z_streamp,const Bytef*, int);


	extern INFLATE_FUNC				INFLATE;
	extern INFLATEINIT_FUNC			INFLATEINIT;
	extern INFLATEEND_FUNC			INFLATEEND;
	extern INFLATEINIT2_FUNC		INFLATEINIT2;
	extern INFLATESETDICTIONARY_FUNC INFLATESETDICTIONARY;

	extern DEFLATEINIT_FUNC 		DEFLATEINIT;
	extern DEFLATE_FUNC				DEFLATE;
	extern DEFLATEEND_FUNC			DEFLATEEND;
	extern DEFLATESETDICTIONARY_FUNC DEFLATESETDICTIONARY;
#else
	#include <zlib.h>
	#include <zconf.h>
	#define INFLATE					inflate
	#define INFLATEINIT				inflateInit_
	#define INFLATEEND				inflateEnd
	#define INFLATEINIT2			inflateInit2_
	#define INFLATESETDICTIONARY    inflateSetDictionary
	#define DEFLATE 				deflate
	#define DEFLATEINIT				deflateInit_
	#define DEFLATEEND				deflateEnd
	#define DEFLATESETDICTIONARY 	deflateSetDictionary

#endif

#define NORMAL_DATA	 0
#define GZIP_DATA 	 1
#define DEFLATE_DATA 2

int CBDeflate(int cbType,class HTTPAPI *api,HTTPHANDLE HTTPHandle,HTTPRequest* request,HTTPResponse* response);
HTTPIOMapping *gzip(void *in, size_t inSize, int what);
HTTPIOMapping *gunzip(void *in, size_t inSize, int what);

#endif
#endif


