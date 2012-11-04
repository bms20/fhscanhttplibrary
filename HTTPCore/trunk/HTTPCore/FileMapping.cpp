/*
 Copyright (C) 2007 - 2012  fhscan project.
 Andres Tarasco - http://www.tarasco.org/security - http://www.tarlogic.com

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

/** \file FileMapping.cpp
 * Fast HTTP Auth Scanner - HTTP Engine v1.4.
 * ..
 * \author Andres Tarasco Acuna - http://www.tarasco.org
 */

#include "FileMapping.h"

/* TODO: retocar para soportar files >4Gb */

//-----------------------------------------------------------------------------
 HTTPIOMapping::HTTPIOMapping()
 {
/* Initializes a filemapping struct */
assigned = 0;
BufferedPtr = NULL;
MemoryLength = 0;
*BufferedFileName = 0;
KeepFile = 0;
BinaryData = 0;
#ifdef __WIN32__RELEASE__
hMapping = NULL;
hTmpFilename = INVALID_HANDLE_VALUE;
#else
hTmpFilename = -1;
#endif

#ifdef __WIN32__RELEASE__
HTTPCHAR szTmpFile[256];
GetTempPath(256, szTmpFile);
GetTempFileName(szTmpFile, _T("FHScan"), 0, BufferedFileName);
hTmpFilename = CreateFile(BufferedFileName, GENERIC_WRITE | GENERIC_READ,
	FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);

#else
strcpy(BufferedFileName, "/tmp/Fhscan.XXXXXX");
hTmpFilename = mkstemp(BufferedFileName);
#endif
}
//-----------------------------------------------------------------------------

 HTTPIOMapping::~HTTPIOMapping()
 {
 if (BufferedPtr)
 {
 #ifdef __WIN32__RELEASE__
 UnmapViewOfFile(BufferedPtr);
 CloseHandle(hMapping);
 #else
 munmap(BufferedPtr,MemoryLength + (MemoryLength - MemoryLength%4096 ));
 #endif
 }
 #ifdef __WIN32__RELEASE__
 if (hTmpFilename)
 {
 CloseHandle(hTmpFilename);
 if (!KeepFile) {
 DeleteFile(BufferedFileName);
 }
 }
 #else
 if (hTmpFilename>=0)
 {
 close(hTmpFilename);
 if (!KeepFile) {
 remove(BufferedFileName);
 }
 }
 #endif

 assigned=0;
 MemoryLength=0;
 BufferedPtr = NULL;
 BinaryData = 0;

 }
//-----------------------------------------------------------------------------

size_t HTTPIOMapping::OpenFile(HTTPCHAR *lpFileName) {
/* Maps a file into memory */
#ifdef __WIN32__RELEASE__
if (hTmpFilename) {
	CloseHandle(hTmpFilename);
	if (!KeepFile) {
		DeleteFile(BufferedFileName);
	}
}
#else
if (hTmpFilename >= 0) {
	close(hTmpFilename);
	if (!KeepFile) {
		remove(BufferedFileName);
	}
}
#endif
_tcscpy(BufferedFileName, lpFileName);
KeepFile = 1;

#ifdef __WIN32__RELEASE__

hTmpFilename = CreateFile(BufferedFileName, GENERIC_WRITE | GENERIC_READ,
	FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
if (hTmpFilename > 0) {
	MemoryLength = GetFileSize(hTmpFilename, NULL);
}
#else
hTmpFilename = open(BufferedFileName, O_RDWR);
if (hTmpFilename) {
	struct stat buf;
	stat(BufferedFileName, &buf);
	MemoryLength = buf.st_size;
}

#endif

return (GetMappingSize());
}

//-----------------------------------------------------------------------------

 size_t HTTPIOMapping::GetMappingSize(void)
 {
/* returns the size of the memory mapping */
#ifdef __WIN32__RELEASE__
if ((!BufferedPtr) && (hTmpFilename > 0))
#else
if ((!BufferedPtr) && (hTmpFilename >= 0))
#endif
{
UpdateFileMapping();
}
return (MemoryLength);
}
//-----------------------------------------------------------------------------
 HTTPCHAR *HTTPIOMapping::GetMappingData(void)
 {
/* returns a pointer to the mapped memory */
#ifdef __WIN32__RELEASE__
if ((!BufferedPtr) && (hTmpFilename > 0))
#else
if ((!BufferedPtr) && (hTmpFilename >= 0))
#endif
{
UpdateFileMapping();
}
return ((HTTPCHAR*)BufferedPtr);
}
//-----------------------------------------------------------------------------
 int HTTPIOMapping::IsAssigned(void)
 {
 return (assigned);
 }
//-----------------------------------------------------------------------------

HTTPCHAR *HTTPIOMapping::UpdateFileMapping() {
if (MemoryLength == 0) {
return (NULL);
}
#ifdef __WIN32__RELEASE__
if (hTmpFilename == INVALID_HANDLE_VALUE)
#else
if (hTmpFilename < 0)
#endif
{
return (NULL);
}
#ifdef __WIN32__RELEASE__
if (!hMapping) {
hMapping = CreateFileMapping(hTmpFilename, NULL, PAGE_READWRITE, 0, 0, NULL);
BufferedPtr = (char*) MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
}
if (!BufferedPtr) {
#else
BufferedPtr = (char*) mmap(0,
	MemoryLength + (MemoryLength - MemoryLength % 4096), PROT_READ | PROT_WRITE,
	MAP_SHARED, hTmpFilename, 0);
if (BufferedPtr == (void*)-1) {
_tprintf(_T("mmap Error - Memory Length: %i - File(%i) %s\n"), MemoryLength,
	hTmpFilename, BufferedFileName);
perror("mmap");
#endif
BufferedPtr = NULL;
MemoryLength = 0;
return (NULL);
}

assigned = 1;
return ((HTTPCHAR*)BufferedPtr);
}
//-----------------------------------------------------------------------------
 size_t HTTPIOMapping::WriteMappingData(size_t length, char *lpData )
 {
 #ifdef _UNICODE
 if (BinaryData)
 {
 return ( WriteMappingBinaryData(length,lpData));
 }
 #endif
 #ifdef __WIN32__RELEASE__
 if (hTmpFilename==INVALID_HANDLE_VALUE)
 #else
 if (hTmpFilename<0)
 #endif
 {
 return (0);
 } else
 {
 if ((lpData) && (length))
 {
 #ifdef __WIN32__RELEASE__
 #ifdef _UNICODE
 BinaryData = 1;
 WriteFile(hTmpFilename, (unsigned char*)lpData, length, &lpBufferSize, NULL);
 #else
 WriteFile(hTmpFilename, (unsigned char*)lpData, length, &lpBufferSize, NULL);
 #endif
 #else
 int ret;
 int err = 0;
 do {
 ret = write(hTmpFilename, lpData, length);
 if (ret == -1) {
 #ifdef _DBG_
 perror("Write failed - retry..");
 #endif
 err++;
 Sleep(100);
 if (err > 20) {
 return (0); /* No more waiting */
}}}
while (ret == -1);
#endif
MemoryLength += length;
return (MemoryLength);
}} return (0);
}
//-----------------------------------------------------------------------------
 #ifdef _UNICODE
 size_t HTTPIOMapping::WriteMappingBinaryData(size_t length, char *lpData )
 {
 #ifdef __WIN32__RELEASE__
 if (hTmpFilename==INVALID_HANDLE_VALUE)
 #else
 if (hTmpFilename<0)
 #endif
 {
 return (0);
 } else
 {
 if ((lpData) && (length))
 {
 BinaryData = 1;
 #ifdef __WIN32__RELEASE__
 WriteFile(hTmpFilename,(unsigned char*)lpData,length,&lpBufferSize,NULL);
 #else
 int ret;
 int err = 0;
 do {
 ret = write(hTmpFilename,lpData,length);
 if (ret==-1)
 {
 #ifdef _DBG_
 perror("Write failed - retry..");
 #endif
 err++;
 Sleep(100);
 if (err>20)
 {
 return(0); /* No more waiting */
}}}
while (ret == -1);
#endif
MemoryLength += length;
return (MemoryLength);
}} return (0);
}
#endif

//-----------------------------------------------------------------------------
 int HTTPIOMapping::IsBinaryData(void)
 {
 return(BinaryData);
 }
//-----------------------------------------------------------------------------
void HTTPIOMapping::SetBinaryData(int i) {
BinaryData = i;
}
//-----------------------------------------------------------------------------
