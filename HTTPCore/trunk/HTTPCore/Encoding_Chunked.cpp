/*
Copyright (C) 2007 - 2009  fhscan project.
Andres Tarasco - http://www.tarasco.org/security

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
/** \file Encoding_Chunked.cpp
 * Fast HTTP Auth Scanner -  Chunk encoding for handling transfer encoding.
 *
 * \author Andres Tarasco Acuna - http://www.tarasco.org (c) 2007 - 2008
*/
#include "Encoding_Chunked.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE
#endif


/******************************************************************************/
//! This function decodes the buffer returned by the remote HTTP Server when "Chunk encoding" is enabled.
/*!
	\param lpBuffer Buffer returned by the http server (Without headers )
	\param encodedlen length of lpBuffer
	\return Pointer to a Filemapping structure where the data have been decoded.
	\note If the function fails due to malformed or incomplete datachunks, NULL is returned instead. If that happends, the user must use the original lpBuffer data
*/
/******************************************************************************/
class HTTPIOMapping *DecodeChunk(char *lpBuffer, unsigned int encodedlen)
{

    char *encoded=lpBuffer;
    char chunkcode[MAX_CHUNK_LENGTH+1];
	char *p;
    unsigned long chunk=1;
	HTTPIOMapping *HTTPIoMapping = NULL;
    
    do {
        if (lpBuffer!=encoded){
			if (encodedlen<=2) {
				break;
			}
            encoded+=2;
            encodedlen-=2;
        }
        if (encodedlen>=MAX_CHUNK_LENGTH) {
			memcpy(chunkcode,encoded,MAX_CHUNK_LENGTH);
            chunkcode[MAX_CHUNK_LENGTH]='\0';
        } else {
            memcpy(chunkcode,encoded,encodedlen);
            chunkcode[encodedlen]='\0';
        }
        p=strstr(chunkcode,"\r\n");
        if (!p)  //Do not decode block, due to chunk error
        {		 //Maybe we should append this data block
			if (HTTPIoMapping)
			{
				delete HTTPIoMapping;
			}
			#ifdef _DBG_
				printf("DecodeChunk::error...\n");
			#endif
            return(NULL);
        }
        *p='\0';
        chunk=strtol(chunkcode,NULL,16);
        if ( (unsigned int) encodedlen > strlen(chunkcode)+ 2 + chunk) 
		{
			if (!HTTPIoMapping)
			{
				HTTPIoMapping = new HTTPIOMapping;
				if (!HTTPIoMapping) return(NULL);
				if (!HTTPIoMapping->InitializeFileMapping(chunk,encoded+2+strlen(chunkcode)))
				{
					delete HTTPIoMapping;
					return(NULL);
				}					
			} else 
			{
				HTTPIoMapping->WriteMappingData(chunk,encoded+2+strlen(chunkcode));
			}            
            encodedlen-=2+chunk+strlen(chunkcode);
            encoded+=2+chunk+strlen(chunkcode);
        } else {
			if (!HTTPIoMapping)
			{
				HTTPIoMapping = new HTTPIOMapping;
				if (!HTTPIoMapping) return(NULL);
				if (!HTTPIoMapping->InitializeFileMapping(encodedlen-strlen(chunkcode)-2,encoded+2+strlen(chunkcode)))
				{
					delete HTTPIoMapping;
					return(NULL);
				}					
			} else 
			{
				HTTPIoMapping->WriteMappingData(encodedlen-strlen(chunkcode)-2,encoded+2+strlen(chunkcode));
			}
            encodedlen=0;
        }
    } while ( (encodedlen>0) && (chunk>0) );

//	HTTPIoMapping->UpdateFileMapping();
	return(HTTPIoMapping);

}

/******************************************************************************/
//! CallBack Function. This function is called from the DoCallBack() function once its registered and will intercept the callback information.
/*!
	\param cbType CallBack Source Type. Valid options are CBTYPE_CLIENT_REQUEST , CBTYPE_CLIENT_RESPONSE , CBTYPE_BROWSER_REQUEST , CBTYPE_SERVER_RESPONSE
	\param HTTPHandle HTTP Connection Handle with information about remote target (like ip address, port, ssl, protocol version,...)
	\param prequest struct containing all information related to the HTTP Request.
	\param presponse struct containing information about http reponse. This parameter could be NULL if the callback type is CBTYPE_CLIENT_REQUEST or CBTYPE_CLIENT_RESPONSE because request was not send yet.
	\return the return value CBRET_STATUS_NEXT_CB_CONTINUE indicates that the request (modified or not) its ok. If a registered handler blocks the request then CBRET_STATUS_CANCEL_REQUEST is returned. This value indicates that the response is locked
    \note This function does not block requests, only tries to decode HTTP response.
*/
/******************************************************************************/
int CBDecodeChunk(int cbType,class HTTPAPI	*api,HTTPHANDLE HTTPHandle,httpdata*  request,httpdata* response)
{

	if ((cbType == CBTYPE_CLIENT_RESPONSE) || (cbType == CBTYPE_PROXY_RESPONSE) )
	{
	 if (response) {
		char *p=response->GetHeaderValue("Transfer-Encoding:",0);
		if (p)
		{
			if (strnicmp(p,"chunked",7)==0) 
			{
				class HTTPIOMapping *newFileMapping = DecodeChunk(response->Data,response->DataSize);				
				if (newFileMapping)
				{
					//printf("llamamos desde chunked: %8.8X -  %i bytes\n",newFileMapping, newFileMapping->GetMappingSize());
					//printf("Contenido: %s\n", newFileMapping->GetMappingData());
					response->UpdateAndReplaceFileMappingData(newFileMapping);
					//printf("Volvemos a chunked\n");
					response->RemoveHeader("Transfer-Encoding: ");
					char tmp[256];
					sprintf(tmp,"Content-Length: %i\r\n",response->DataSize);
					response->AddHeader(tmp);
				}
			}
			free(p);
		}
	 }
	}

	return(CBRET_STATUS_NEXT_CB_CONTINUE);

}

