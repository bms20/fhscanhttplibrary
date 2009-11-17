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
#include "FileMapping.h"
#include <stdio.h>
#include <string.h>

/* TODO: retocar para soportar files >4Gb */

/******************************************************************************/
HTTPIOMapping::HTTPIOMapping()
{
	assigned = 0;
	BufferedPtr = NULL;
	MemoryLength = 0;
	*BufferedFileName=0;
	#ifdef __WIN32__RELEASE__
	hMapping = NULL;
	hTmpFilename = INVALID_HANDLE_VALUE;
	#else
	hTmpFilename = -1;
	#endif

	BufferedPtr = NULL;
}
/******************************************************************************/
HTTPIOMapping::HTTPIOMapping(unsigned int DataSize = 0, char *lpData = NULL)
{
	assigned = 0;
	BufferedPtr = NULL;
	MemoryLength = 0;
	BufferedFileName[0]='\0';
	#ifdef __WIN32__RELEASE__
	hMapping = NULL;
	hTmpFilename = INVALID_HANDLE_VALUE;
	#else
	hTmpFilename = -1;
	#endif
	BufferedPtr = NULL;
	InitializeFileMapping(DataSize,lpData);
}
/******************************************************************************/
HTTPIOMapping::~HTTPIOMapping()
{
	assigned=0;

	if (BufferedPtr)
	{
		#ifdef __WIN32__RELEASE__
			UnmapViewOfFile(BufferedPtr);
			CloseHandle(hMapping);
		#else
			munmap(BufferedPtr,MemoryLength+1);
		#endif
	}
	#ifdef __WIN32__RELEASE__
	if (hTmpFilename)
	{
		CloseHandle(hTmpFilename);
		DeleteFileA(BufferedFileName);
	}
	#else
	if (hTmpFilename>=0)
	{
		close(hTmpFilename);
		remove(BufferedFileName);
	}
	#endif

	MemoryLength=0;

}
/******************************************************************************/

unsigned long HTTPIOMapping::GetMappingSize(void)
{
	#ifdef __WIN32__RELEASE__
	if ((!BufferedPtr) && (hTmpFilename>0) )
	#else
	if ((!BufferedPtr) && (hTmpFilename>=0) )
	#endif
	{
		//printf("GetMappingSize::LLamada a   UpdateFileMapping()\n");
		UpdateFileMapping();
	}
	return(MemoryLength);
}
/******************************************************************************/
char *HTTPIOMapping::GetMappingData(void)
{
	#ifdef __WIN32__RELEASE__
	if ((!BufferedPtr) && (hTmpFilename>0) )
	#else
	if ((!BufferedPtr) && (hTmpFilename>=0) )
	#endif
	{
		UpdateFileMapping();
	}
	return(BufferedPtr);
}
/******************************************************************************/
int HTTPIOMapping::IsAssigned(void)
{
	return (assigned);
}
/******************************************************************************/
int HTTPIOMapping::InitializeFileMapping(unsigned int DataSize,char *lpData)
{

#ifdef __WIN32__RELEASE__
			char szTmpFile[256];
			GetTempPathA (256, szTmpFile);
			GetTempFileNameA (szTmpFile, "FHScan",0,BufferedFileName);
#ifdef _DBG_
			printf("Usando fichero temporal: %s\n",BufferedFileName);
#endif
			hTmpFilename = CreateFileA ( BufferedFileName,
				GENERIC_WRITE | GENERIC_READ,
				FILE_SHARE_WRITE,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_TEMPORARY,
				NULL);
			if ( hTmpFilename == INVALID_HANDLE_VALUE) 
			{
#ifdef _DBG_
				printf("GetFileMapping Error: Unable to create temporary filename\n");
#endif
            	MemoryLength = 0;
				assigned= 0;
				return(0);
			}
#else
			strcpy(BufferedFileName,tempnam(NULL,"FHScan") );
			hTmpFilename  = open(BufferedFileName,O_RDWR | O_CREAT , S_IRUSR | S_IWUSR | S_IRGRP);
			if (hTmpFilename<0)
			{
            	MemoryLength = 0;
				assigned= 0;
				return(0);
			}
#endif

			WriteMappingData(DataSize,lpData);
			return(1);
}
/******************************************************************************/

char *HTTPIOMapping::UpdateFileMapping()
{
	#ifdef __WIN32__RELEASE__
	if ( hTmpFilename == INVALID_HANDLE_VALUE)
	#else
	if ( hTmpFilename <0)
	#endif
	{
		assigned = 0;
		return(NULL);
	}
	#ifdef __WIN32__RELEASE__
	if (!hMapping)
	{
		hMapping = CreateFileMapping (hTmpFilename,NULL,PAGE_READWRITE,0,0,NULL);
		BufferedPtr = (char*) MapViewOfFile (hMapping , FILE_MAP_ALL_ACCESS, 0,0,0);
	}
	#else
	BufferedPtr = (char*) mmap (0, MemoryLength, PROT_READ | PROT_WRITE, MAP_SHARED, hTmpFilename, 0);
	#endif
	if (!BufferedPtr)
	{
		assigned = 0;
		MemoryLength = 0;
		return(NULL);
	}

	assigned = 1;
	return(BufferedPtr);
}
/******************************************************************************/
int HTTPIOMapping::WriteMappingData(unsigned int length, char *lpData )
{
#ifdef __WIN32__RELEASE__
	if (hTmpFilename==INVALID_HANDLE_VALUE)
#else
if (hTmpFilename<0)
#endif
	{
		return (InitializeFileMapping(length,lpData));
	} else
	{
		if ((lpData) && (length))
		{
			#ifdef __WIN32__RELEASE__
				WriteFile(hTmpFilename,(unsigned char*)lpData,length,&lpBufferSize,NULL);
			#else
				write(hTmpFilename,lpData,length);
			#endif
			MemoryLength += length;
			return(MemoryLength);
		}
	}
	return(0);
}
/*******************************/
