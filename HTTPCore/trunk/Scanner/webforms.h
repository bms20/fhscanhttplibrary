#ifndef __WEBFORMS_H
#define __WEBFORMS_H
#include <stdio.h>
#ifdef __WIN32__RELEASE__
#include <windows.h>
#endif


#define RAWUSER   _T("!!!RAWUSER!!!")
#define RAWPASS   _T("!!!RAWPASS!!!")
#define B64USER   _T("!!!B64USER!!!")
#define B64PASS   _T("!!!B64PASS!!!")
#define MD5USER   _T("!!!MD5USER!!!")
#define MD5PASS   _T("!!!MD5PASS!!!")
#define RAWIPAD   _T("!!!RAWIPAD!!!")
#define RAWPORT   _T("!!!RAWPORT!!!")
#define RAWTIME   _T("!!!RAWTIME!!!")
#define HD5USER   _T("!!!HD5USER!!!")
#define HD5PASS   _T("!!!HD5PASS!!!")

#ifndef HTTPHANDLE
 #define HTTPHANDLE int
#endif
   
#define NEEDUSER  1
#define NEEDPASS  2


int CheckWebformAuth(HTTPAPI *api,HTTPHANDLE HTTPHandle,HTTPSession* data, int indexpos);

#endif
