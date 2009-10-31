#ifndef _ENCODING_CHUNKED_
#define _ENCODING_CHUNKED_

#include "../CallBacks.h"

#define MAX_CHUNK_LENGTH						10
#define ERROR_MORE_DATA_NEEDED 					-1
#define ERROR_PARSING_DATA     					0xFFFFFF

int CBDecodeChunk(int cbType,class HTTPAPI	*api,HTTPHANDLE HTTPHandle,httpdata* request,httpdata* response);
//int ParseDataChunks(char *lpBuffer, unsigned int encodedlen);

#endif

