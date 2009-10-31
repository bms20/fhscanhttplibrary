//#define _DBG_
/** \file Encoding_Deflate.cpp
 * Fast HTTP Auth Scanner -  gzip and deflate algoritms for handling content encoding.
 * This module is linked with ZLIB 1.2.3 library
 *
 * NOTE: Some additional code was ripped from zlib "gzio.c" to allow "on-the-fly"
 * decoding of gzip streams
 * \author Andres Tarasco Acuna - http://www.tarasco.org (c) 2007 - 2008
*/
#ifdef _ZLIB_SUPPORT_

#include "Encoding_Deflate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

 #ifdef __WIN32__RELEASE__
	HMODULE						f_hLIBZ = NULL;
	INFLATE_FUNC				INFLATE;
	INFLATEINIT_FUNC			INFLATEINIT;
	INFLATEEND_FUNC				INFLATEEND;
	INFLATEINIT2_FUNC			INFLATEINIT2;
 #endif

#define CHUNK 16384
/******************************************************************************/
//! This function extracts one byte from a gzip stream.
/*!
	\param strm pointer to a previously initialized z_stream structure.
	\return The integer value stored in the first byte of the stream or EOF if there is no more data.
*/
/******************************************************************************/

__inline static int get_byte(z_stream *strm)
{
 if (strm->avail_in==0) {
     return EOF;
 }
  strm->avail_in--;
  return *(strm->next_in)++;
}

/******************************************************************************/
//! Decompress from gziped/deflated buffer and returns a pointer to the gunziped data.
/*!
	\param in pointer to the buffer containing the compressed stream.
	\param inSize length of in buffer
	\param what type of compression. This value can be DEFLATE_DATA or GZIP_DATA).
	\return Pointer to an HTTPIOMapping class that contains the decoded buffer.
	\note If the function fails due to malformed or incomplete compressed stream,
	NULL is returned instead.
*/
/******************************************************************************/
HTTPIOMapping *gunzip(char *in, int inSize, int what)
{
	int ret;
    unsigned have;
	z_stream strm;
	unsigned char out[CHUNK];
	HTTPIOMapping *HTTPIoMapping = NULL;


	if ( (!inSize) || (!in) ) {
		return(NULL);
	}

	/* allocate inflate state */
	strm.zalloc = Z_NULL;
	strm.zfree =  Z_NULL;
	strm.opaque = Z_NULL;
    strm.avail_in = strm.avail_out = 0;
	strm.next_in  = strm.next_out  = 0;

	strm.avail_in = inSize;
	strm.next_in=(Bytef*)in;

	if (what == GZIP_DATA )
	{
		unsigned int len;
		int c;
		ret = INFLATEINIT2(&strm,-MAX_WBITS,ZLIB_VERSION,sizeof(z_stream));
		if (ret != Z_OK) return(NULL);

		memset(out,0,sizeof(out));
		/* Peek ahead to check the gzip magic header */
		if (strm.next_in[0] != 0x1f ||
			strm.next_in[1] != 0x8b) {
			#ifdef _DBG_
				printf("gunzip(): INVALID Magic gzip header\n");
			#endif
            	INFLATEEND(&strm);
				return (NULL);;
		}
		strm.avail_in -= 2;
		strm.next_in += 2;

		int method= get_byte(&strm);/* method byte */
		int flags = get_byte(&strm);/* flags byte */

		/* gzip flag byte */
		#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
		#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
		#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
		#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
		#define COMMENT      0x10 /* bit 4 set: file comment present */
		#define RESERVED     0xE0 /* bits 5..7: reserved */

		if (method != Z_DEFLATED || (flags & RESERVED) != 0)
		{
		#ifdef _DBG_
			printf("gunzip(): Method or flags error: %i - %i\n",method,flags);
		#endif
        	INFLATEEND(&strm);
			return NULL;
		}
		/* Discard time, xflags and OS code: */
		strm.avail_in-=6;
		strm.next_in+=6;

		if ((flags & EXTRA_FIELD) != 0) { /* skip the extra field */
			len  =  (uInt)get_byte(&strm);
			len += ((uInt)get_byte(&strm))<<8;
			/* len is garbage if EOF but the loop below will quit anyway */
			while (len-- != 0 && get_byte(&strm) != EOF) ;
		}

		if ((flags & ORIG_NAME) != 0) { /* skip the original file name */
			while ((c = get_byte(&strm)) != 0 && c != EOF) ;
		}
		if ((flags & COMMENT) != 0) {   /* skip the .gz file comment */
			while ((c = get_byte(&strm)) != 0 && c != EOF) ;
		}
		if ((flags & HEAD_CRC) != 0) {  /* skip the header crc */
			for (len = 0; len < 2; len++) (void)get_byte(&strm);
		}
   }  else if (what == DEFLATE_DATA )
   {
		ret = INFLATEINIT(&strm,ZLIB_VERSION,sizeof(z_stream));
		if (ret != Z_OK) return(NULL);
    }   else return (NULL);

	/* run inflate() on input until output buffer not full */
	do {
            strm.avail_out = sizeof(out);
            strm.next_out = out;
            ret = INFLATE(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
            case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				(void)INFLATEEND(&strm);
				if (HTTPIoMapping)
				{
					delete HTTPIoMapping;
				}
				return(NULL);
			}
			have = CHUNK - strm.avail_out;
			if (have>0) 
			{

				if (!HTTPIoMapping)
				{
					HTTPIoMapping = new HTTPIOMapping;
					if (!HTTPIoMapping) return(NULL);
					if (!HTTPIoMapping->InitializeFileMapping(have,(char*)out))
					{
						delete HTTPIoMapping;
						return(NULL);
					}					
				} else 
				{
					HTTPIoMapping->WriteMappingData(have,(char*)out);
				}
			}
	} while (strm.avail_out == 0);
	(void)INFLATEEND(&strm);

	//TODO: Verificar que sucede con buffers de tamaño 0.
	return(HTTPIoMapping);
	

}

/******************************************************************************/
//! CallBack Function. This function is called from the DoCallBack() function once its registered and will intercept the callback information.
/*!
	\param cbType CallBack Source Type. Valid options are CBTYPE_CLIENT_REQUEST , CBTYPE_CLIENT_RESPONSE , CBTYPE_BROWSER_REQUEST , CBTYPE_SERVER_RESPONSE
	\param HTTPHandle HTTP Connection Handle with information about remote target (like ip address, port, ssl, protocol version,...)
	\param request struct containing all information related to the HTTP Request.
	\param response struct containing information about http reponse. This parameter could be NULL if the callback type is CBTYPE_CLIENT_REQUEST or CBTYPE_CLIENT_RESPONSE because request was not send yet.
	\return the return value CBRET_STATUS_NEXT_CB_CONTINUE indicates that the request (modified or not) its ok. If a registered handler blocks the request then CBRET_STATUS_CANCEL_REQUEST is returned. This value indicates that the response is locked
	\note This function does not block requests, only tries to decode gzip or deflated HTTP response.
*/
/******************************************************************************/
int CBDeflate(int cbType,class HTTPAPI *api,HTTPHANDLE HTTPHandle,httpdata* request,httpdata* response)
{


#ifdef __WIN32__RELEASE__

	if (!f_hLIBZ)
	{
		f_hLIBZ = LoadLibraryA("zlib1.dll");
		if (!f_hLIBZ)
		{
			printf("## FATAL - ZLIB LIBRARY NOT FOUND\n");
			exit(1);
		}
		INFLATE				= (INFLATE_FUNC)GetProcAddress(f_hLIBZ,		"inflate");
		INFLATEINIT         = (INFLATEINIT_FUNC)GetProcAddress(f_hLIBZ, "inflateInit_");
		INFLATEEND          = (INFLATEEND_FUNC)GetProcAddress(f_hLIBZ,  "inflateEnd");
		INFLATEINIT2        = (INFLATEINIT2_FUNC)GetProcAddress(f_hLIBZ,"inflateInit2_");

		if (!INFLATE || !INFLATEINIT || !INFLATEEND || !INFLATEINIT2)
		{
			printf("## FATAL - ZLIB LIBRARY IMPORTS ERROR\n");
			exit(1);
		}
//		printf("\n############ LIBRERIAS CARGADAS ##########\n");

	}
#endif

	if ( (cbType == CBTYPE_CLIENT_REQUEST) || (cbType == CBTYPE_PROXY_REQUEST) )
	{
		if (request)
		{
			if (strncmp(request->Header,"CONNECT ",8)!=0)
			{
				request->RemoveHeader("Accept-Encoding: ");
				request->AddHeader("Accept-Encoding: gzip, deflate");
			}
		}
		return (CBRET_STATUS_NEXT_CB_CONTINUE);
	} else 	if ( (cbType == CBTYPE_CLIENT_RESPONSE) || (cbType == CBTYPE_PROXY_RESPONSE) )
	{
		int type = NORMAL_DATA;

		if ( (!response) || (!response->HeaderSize) || (!response->Header) )  {
		   return (CBRET_STATUS_NEXT_CB_CONTINUE);
		}
		char *encoding=response->GetHeaderValue("Content-Encoding:",0);
		if (!encoding)
			return(CBRET_STATUS_NEXT_CB_CONTINUE);

		char *p = strstr(encoding,"deflate");
		if (p)
			type= DEFLATE_DATA;
		else {
		   p = strstr(encoding,"gzip");
		   if (p)  type= GZIP_DATA;
		}

		if (type != NORMAL_DATA)
		{
			//char *decoded = (char *) (response->Data, response->DataSize, &total, type);
			HTTPIOMapping *decoded = gunzip(response->Data, response->DataSize,type);
			if (decoded)
			{
				#ifdef _DBG_
					printf("CBDeflate(): uncompressed %i bytes to %i. Data: %s\n",response->DataSize,total,p);
				#endif
				response->UpdateAndReplaceFileMappingData(decoded);
				response->RemoveHeader("Content-Encoding:");
				response->RemoveHeader("Content-Length:");
				char tmp[256];
				sprintf(tmp,"Content-Length: %i\r\n",response->DataSize);
				response->AddHeader(tmp);
			} else 
			{
				#ifdef _DBG_
					printf("CBDeflate(): Error decoding buffer with %s\n",p);
				#endif
			}
		}
		free(encoding);
	}
	return (CBRET_STATUS_NEXT_CB_CONTINUE);

}
#endif





