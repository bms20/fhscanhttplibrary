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
/** \file FileMapping.h
 * Fast HTTP Auth Scanner - HTTP Engine v1.4.
 * This include file contains all needed information to manage File mappings.
 * \author Andres Tarasco Acuna - http://www.tarasco.org
 */
#ifndef __FILEMAPPING_H__
#define __FILEMAPPING_H__

#include "Build.h"
#ifdef __WIN32__RELEASE__
 #include <sys/timeb.h>
 #include <process.h>
 #include <time.h>
 #include <windows.h>
#else
 #include <stdlib.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <sys/socket.h>
 #include <sys/ioctl.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <pthread.h>
 #include <ctype.h>
 #include <time.h>
 #include <sys/timeb.h>
#endif


class HTTPIOMapping
{
   int			   assigned;
   char			  *BufferedPtr;
   size_t			MemoryLength;
   char			   BufferedFileName[MAX_PATH];
  #ifdef __WIN32__RELEASE__
   HANDLE		   hTmpFilename;
   HANDLE          hMapping;
   DWORD lpBufferSize;
  #else
   int			  hTmpFilename;
  #endif
  int 			   KeepFile; /* Do not delete file */
     
   char *UpdateFileMapping(); //Mapea los datos del fichero con bufferptr
public:
   HTTPIOMapping();   
   ~HTTPIOMapping();   
   size_t        WriteMappingData(size_t , char *lpData); //escribe los datos y llama a updatefileMapping() si es necesario.
   size_t HTTPIOMapping::OpenFile(HTTPCHAR *lpFileName);
   size_t        GetMappingSize(void);
   char*		 GetMappingData(void);
   int			 IsAssigned(void);

};
/*******************************/
#endif

