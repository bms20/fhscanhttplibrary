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

/** \file Threading.cpp
 * Fast HTTP Auth Scanner - HTTP Engine v1.4.
 * ..
 * \author Andres Tarasco Acuna - http://www.tarasco.org
 */

#include "Threading.h"

//-----------------------------------------------------------------------------
 Threading::Threading()
 {
 #ifdef WIN32
 InitializeCriticalSection(&mutex);
 #else
 //	pthread_mutexattr_settype(&mutexattr,PTHREAD_MUTEX_RECURSIVE); // Set the mutex as recursive
 //	pthread_mutex_init((pthread_mutex_t*)&mutex, &mutexattr);  // create the mutex with the attributes set
 //	pthread_mutexattr_destroy(&mutexattr);
 mutex =PTHREAD_MUTEX_INITIALIZER;

 #endif
 Thread = 0;
 }
//-----------------------------------------------------------------------------
Threading::~Threading() {
#ifdef WIN32
	DeleteCriticalSection((CRITICAL_SECTION*)&mutex);
#else
	pthread_mutex_destroy((pthread_mutex_t*)&mutex);
#endif
}

//-----------------------------------------------------------------------------
 void Threading::LockMutex(void)
 {
 #ifdef WIN32
 EnterCriticalSection((CRITICAL_SECTION*)&mutex);
 #else
 pthread_mutex_lock ((pthread_mutex_t*)&mutex);
 #endif
 }
//-----------------------------------------------------------------------------
void Threading::UnLockMutex(void) {
#ifdef WIN32
	LeaveCriticalSection((CRITICAL_SECTION*)&mutex);
#else
	pthread_mutex_unlock((pthread_mutex_t*)&mutex);
#endif
}

//-----------------------------------------------------------------------------
 int Threading::InitThread(void* func, void* parameter)
 {
 #ifdef WIN32
 DWORD dwThread;
 Thread=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE) func, (LPVOID) parameter, 0, &dwThread);
 #else
 void* (*foo)(void*) = (void*(*)(void*))func;
 pthread_create(&Thread, NULL, foo, (void *)parameter);
 #endif
 return(1);
 }
//-----------------------------------------------------------------------------
int Threading::EndThread(void) {
#ifdef WIN32
	TerminateThread(Thread, 0);
#else
	pthread_cancel(Thread);
#endif
	return (1);
}
//-----------------------------------------------------------------------------
