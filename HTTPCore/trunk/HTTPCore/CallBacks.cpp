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
/** \file Callbacks.cpp
 * Fast HTTP Auth Scanner - HTTP Engine v1.4.
 * ..
 * \author Andres Tarasco Acuna - http://www.tarasco.org
 */

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
#include "CallBacks.h"
//#include "Build.h"


/*******************************************************************************************************/
HTTPCALLBACK::HTTPCALLBACK()
{
	CBItems = 0;
	CBList = NULL;
	ParentHTTPApi = NULL;
}
/*******************************************************************************************************/
HTTPCALLBACK::~HTTPCALLBACK()
{
	for (unsigned int i=0;i<CBItems ;i++)
    {
		if (CBList[i].lpDescription) free(CBList[i].lpDescription);			
    }
	if (CBList) free(CBList);
	CBList = NULL;
	CBItems = 0;
}

/**********************************************************************************************************************/
//! This function Registers an HTTP Callback Handler and is called by external plugins
/*!
	\param cbType CallBack Type. Valid options are CBTYPE_CLIENT_REQUEST , CBTYPE_CLIENT_RESPONSE , CBTYPE_BROWSER_REQUEST , CBTYPE_SERVER_RESPONSE. Use CBTYPE_CALLBACK_ALL to match every possible callback (including undefined ones).
    \param cb CallBack Address. This is the Address of the CallBack Function that will receive HTTP parameters.
    \return If an error is detected, for example an already added callback, 0 is returned.
	\note Registered callback functions are also responsible for handling undefined CallBack types. If a registered callback function does not know how to handle an specific callback type must ingore the data.
    For more information read the plugin development documentation.
*/
/**********************************************************************************************************************/
int HTTPCALLBACK::RegisterHTTPCallBack(unsigned int cbType, HTTP_IO_REQUEST_CALLBACK cb,HTTPCSTR Description)
{

	for (unsigned int i=0;i<CBItems;i++)
	{
		if (CBList[i].cb == cb) return( 0 );
	}
	CBList=(PCB_LIST)realloc(CBList,sizeof(CB_LIST)*++CBItems);
    CBList[CBItems-1].cbType=cbType;
    CBList[CBItems-1].cb=cb;
	if (Description)
	{
		CBList[CBItems-1].lpDescription = _tcsdup(Description);
	} else {
		CBList[CBItems-1].lpDescription = NULL;
	}
	return(1);

}
/**********************************************************************************************************************/
//! This function unregisters a previously loaded Callback
/*!
	\param cbType CallBack Type. Valid options are CBTYPE_CLIENT_REQUEST , CBTYPE_CLIENT_RESPONSE , CBTYPE_BROWSER_REQUEST , CBTYPE_SERVER_RESPONSE or CBTYPE_CALLBACK_ALL to match every possible callback
    \param cb CallBack Address. This is the Address of the CallBack Function that was receiving HTTP parameters.
	\return Returns the number of removed Callbacks.
	\note Its possible to remove all Callback types against a function using CBTYPE_CALLBACK_ALL.
*/
/**********************************************************************************************************************/

int  HTTPCALLBACK::RemoveHTTPCallBack(unsigned int cbType, HTTP_IO_REQUEST_CALLBACK cb)
{
    unsigned int ret=0;
    for (unsigned int i=0;i<=CBItems -1;i++)
    {
        if ( (cb==NULL) || (CBList[i].cb == cb ) )
        {
            if (CBList[i].cbType & cbType)
            {
                CBList[i].cb=NULL;
				if (CBList[i].lpDescription)
				{
					free(CBList[i].lpDescription);
					CBList[i].lpDescription = NULL;
				}
                ret++;
            }
        }
    }
    if (ret==CBItems) 
    {
        free(CBList);
        CBList=NULL;
        CBItems=0;
    }
    return(ret);
}
/**********************************************************************************************************************/
//! CallBack Dispatcher. This function is called from the HTTPCore module ( SendRawHttHTTPSession*() ) and from the HTTPProxy Module DispatchHTTPProxyRequest() and will send http information against registered callbacks
/*!
	\param cbType CallBack Source Type. The value specifies where the data comes from. The valid options are CBTYPE_CLIENT_REQUEST , CBTYPE_CLIENT_RESPONSE , CBTYPE_PROXY_REQUEST , CBTYPE_PROXY_RESPONSE
	\param HTTPHandle HTTP Connection Handle with information about remote target (like ip address, port, ssl, protocol version,...)
	\param request struct containing all information related to the HTTP Request.
	\param response struct containing information about http reponse. This parameter could be NULL if the callback type is CBTYPE_CLIENT_RESPONSE or CBTYPE_PROXY_RESPONSE because request was not send yet.
	\return the return value CBRET_STATUS_NEXT_CB_CONTINUE indicates that the request (modified or not) its ok. If a registered handler blocks the request then CBRET_STATUS_CANCEL_REQUEST is returned. This value indicates that the request or response is not authorized to be delivery to the destionation.\n
    \note a Blocked httpdata* request or response could be used for example when a plugin is implementing a popup filtering.
*/
/**********************************************************************************************************************/
int HTTPCALLBACK::DoCallBack(int cbType,HTTPHANDLE HTTPHandle,HTTPRequest* request,HTTPResponse* response)
{ 
    unsigned int i;
	int ret;
	//printf("REALIZANDO CALLBACKS: %i\n",CBItems);
    for (i=0; i<CBItems;i++)
    {
        if ( (CBList[i].cbType & cbType) && (CBList[i].cb) )
		{
		  //printf("LLAMANDO A CALLBACK %i: %s\n",i,CBList[i].lpDescription);
			ret=CBList[i].cb (
                cbType,
				ParentHTTPApi,
				HTTPHandle,
				request,
				response);
            if (ret & CBRET_STATUS_NEXT_CB_BLOCK)
                break;
            if (ret & CBRET_STATUS_CANCEL_REQUEST)
            {
                return(CBRET_STATUS_CANCEL_REQUEST);
            }
        }
    }     
    return( CBRET_STATUS_NEXT_CB_CONTINUE );
}

/*******************************************************************************************************/
