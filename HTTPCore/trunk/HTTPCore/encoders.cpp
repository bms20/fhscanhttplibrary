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
#include "encoders.h"
#include "ntlm.h"
#include "Build.h"


encoders::encoders()
{
}

encoders::~encoders()
{
}


/*************************************************************************************/
HTTPCHAR *encoders::GetNTLMBase64Packet1(HTTPCHAR* destination)
{
	unsigned char NTLMHeader[4096];
	memset(NTLMHeader,'\0',sizeof(NTLMHeader));

	BuildAuthRequest((tSmbNtlmAuthRequest*)NTLMHeader,0,NULL,NULL);
	#ifdef UNICODE
	char destinationAscii[4096];
	encodebase64A(destinationAscii,(char*)NTLMHeader,(int)SmbLength((tSmbNtlmAuthResponse*)NTLMHeader));
	MultiByteToWideChar(CP_ACP, 0, destinationAscii, -1, destination, 4096);
	return(destination);
	#else
	return ( encodebase64A(destination,(char*)NTLMHeader,(int)SmbLength((tSmbNtlmAuthResponse*)NTLMHeader)));
	#endif
}
/*************************************************************************************/
HTTPCHAR *encoders::GetNTLMBase64Packet3(HTTPCHAR* destination, const HTTPCHAR* NTLMresponse, HTTPCSTR lpUsername, HTTPCSTR lpPassword)
{
	char NTLMPacket2[4096];
	char NTLMPacket3[4096];

	memset(NTLMPacket2,0,sizeof(NTLMPacket2));
	memset(NTLMPacket3,0,sizeof(NTLMPacket3));

#ifdef UNICODE
	char NTLMresponseAscii[4096];
	WideCharToMultiByte(CP_ACP, 0, NTLMresponse, -1, NTLMresponseAscii, 4096, NULL, NULL);
	decodebase64A((char*)NTLMPacket2,NTLMresponseAscii);
	char lpUsernameAscii[256];
	char lpPasswordAscii[256];
	WideCharToMultiByte(CP_ACP, 0, lpUsername, -1, lpUsernameAscii, 256, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, lpPassword, -1, lpPasswordAscii, 256, NULL, NULL);
	/* Our NTLM library does not support Unicode, so we must convert data to an Ascii string*/
	buildAuthResponse((tSmbNtlmAuthChallenge*)NTLMPacket2,(tSmbNtlmAuthResponse*)NTLMPacket3,0,lpUsernameAscii,lpPasswordAscii,NULL,NULL);
	char destinationAscii[4096];
	encodebase64A((char*)destinationAscii,(const char*)NTLMPacket3,(int)SmbLength((tSmbNtlmAuthResponse*)NTLMPacket3));
	MultiByteToWideChar(CP_ACP, 0, destinationAscii, -1, destination, 4096);
#else
	decodebase64A((char*)NTLMPacket2,NTLMresponse);
	buildAuthResponse((tSmbNtlmAuthChallenge*)NTLMPacket2,(tSmbNtlmAuthResponse*)NTLMPacket3,0,lpUsername,lpPassword,NULL,NULL);
	encodebase64A((char*)destination,(const char*)NTLMPacket3,(int)SmbLength((tSmbNtlmAuthResponse*)NTLMPacket3));
#endif
	return (destination);

}
/*************************************************************************************/


char* encoders::decodebase64A(char *lpoutput, const char* input)
{
	int inputlen = (int)strlen(input);
	int outputlen = (inputlen * 3) /4 +1;    /*estimated */
	char *output = NULL;
	if (lpoutput)
	{
		output = lpoutput;
	} else {
		output = (char*) malloc( outputlen );
	}

	BIO * b642  = BIO_NEW(BIO_F_BASE64());
	BIO_SET_FLAGS(b642, BIO_FLAGS_BASE64_NO_NL);
	BIO * bmem2 = BIO_NEW_MEM_BUF((void*)input,inputlen);
	bmem2 = BIO_PUSH(b642, bmem2);
	int olen = BIO_READ(bmem2, output, outputlen);
	BIO_FREE_ALL(bmem2);
	if (olen>0)
	{
    	output[olen]=0;
		return(output);
	}
	free(output);
	return(NULL);
}
/*************************************************************************************/
char* encoders::encodebase64A(char *lpoutput, const char* input, size_t inputlen)
{
	if (inputlen)
	{
		BIO * b642  = BIO_NEW(BIO_F_BASE64());
		BIO * bmem2 = BIO_NEW(BIO_S_MEM());
		b642 = BIO_PUSH(b642, bmem2);
		BIO_WRITE(b642, input, (int)inputlen);
		BIO_CTRL(b642,BIO_CTRL_FLUSH,0,NULL);
		BUF_MEM *bptr = NULL;
		BIO_GET_MEM_PTR(b642, &bptr);
		if ( (bptr) && (bptr->length) )
		{
			char *output;
			if (lpoutput)
			{
				output = lpoutput;
			} else {
				output=(char*)malloc(bptr->length+1);
			}
			memcpy(output,bptr->data,bptr->length);
			output[bptr->length]='\0';
			/* remove \n */
			output[bptr->length-1]='\0';
			return ( output);
		}
	}
	return(NULL);
}

#ifdef UNICODE
HTTPCHAR* encoders::decodebase64W(HTTPCHAR *lpoutputW, const HTTPCHAR* inputW)
{
	char *input = (char*)malloc(wcslen(inputW)+1);
	WideCharToMultiByte(CP_ACP, 0, inputW, -1, input, wcslen(inputW)+1, NULL, NULL);

	int inputlen = (int)strlen(input);
	int outputlen = (inputlen * 3) /4 +1;    /*estimated */
	char *output = NULL;
	output = (char*) malloc( outputlen );

	BIO * b642  = BIO_NEW(BIO_F_BASE64());
	BIO_SET_FLAGS(b642, BIO_FLAGS_BASE64_NO_NL);
	BIO * bmem2 = BIO_NEW_MEM_BUF((void*)input,inputlen);
	bmem2 = BIO_PUSH(b642, bmem2);
	int olen = BIO_READ(bmem2, output, outputlen);
	BIO_FREE_ALL(bmem2);
	if (olen>0)
	{
		if (lpoutputW)
		{
			MultiByteToWideChar(CP_ACP, 0, output, olen, lpoutputW, olen+1);
			free(output);
			lpoutputW[olen]=0;
			return(lpoutputW);
		} else {
			HTTPCHAR *outputW = (HTTPCHAR*)malloc(olen * sizeof(HTTPCHAR)+1);
			MultiByteToWideChar(CP_ACP, 0, output, olen, outputW, olen+1);
			free(output);
			outputW[olen]=0;
			return(outputW);
		}
	}
	free(output);
	return(NULL);
}
/*************************************************************************************/
HTTPCHAR* encoders::encodebase64W(HTTPCHAR *lpoutputW, HTTPCSTR inputW, size_t inputlen)
{
	if (inputlen)
	{
		char *input = (char*)malloc(inputlen);
		WideCharToMultiByte(CP_ACP, 0, inputW, inputlen, input, inputlen, NULL, NULL);

		BIO * b642  = BIO_NEW(BIO_F_BASE64());
		BIO * bmem2 = BIO_NEW(BIO_S_MEM());
		b642 = BIO_PUSH(b642, bmem2);
		BIO_WRITE(b642, input, (int)inputlen);
		BIO_CTRL(b642,BIO_CTRL_FLUSH,0,NULL);
		BUF_MEM *bptr = NULL;
		BIO_GET_MEM_PTR(b642, &bptr);
		if ( (bptr) && (bptr->length) )
		{
			
			if (lpoutputW)
			{
				MultiByteToWideChar(CP_ACP, 0, bptr->data, bptr->length, lpoutputW, bptr->length+1);
				lpoutputW[bptr->length]=0;
				return(lpoutputW);
			} else {
				HTTPCHAR* outputW=(HTTPCHAR*)malloc(bptr->length+1);
				MultiByteToWideChar(CP_ACP, 0, bptr->data, bptr->length, outputW, bptr->length+1);
				outputW[bptr->length]=0;
				return(outputW);
			}
		}
	}
	return(NULL);
}
#endif




unsigned char* encoders::GetMD2BinaryHash(char *lpoutput, const char* data, size_t len)
{
	unsigned char *output;
	if (lpoutput)
	{
		output = (unsigned char*)lpoutput;
	} else {
		output = (unsigned char*) malloc( 16 );
	}
	MD2_CTX hash;
	MD2_INIT(&hash);
	MD2_UPDATE(&hash,data,(unsigned long)len);
	MD2_FINAL(output,&hash);
	return(output);
}

char* encoders::GetMD2TextHash(char *lpoutput, const char* data, size_t len)
{
	unsigned char md2sum[16];	
	unsigned char *result;
	if (lpoutput)
	{
		result = (unsigned char*)lpoutput;
	} else {
		result =  (unsigned char*)malloc(16*2+1);
	}
	MD2_CTX hash;
	#define a md2sum

	MD2_INIT(&hash);
	MD2_UPDATE(&hash,data,(unsigned long)len);
	MD2_FINAL(md2sum,&hash);
	snprintf((char *)result,sizeof(md2sum)*2+1,
	 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	 a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
	 a[8], a[9], a[10],a[11],a[12],a[13],a[14],a[15]);
	//result[32]='\0';
	return((char*)result);
}

unsigned char* encoders::GetMD4BinaryHash(char *lpoutput, const char* data, size_t len)
{
	unsigned char *result;
	if (lpoutput)
	{
		result = (unsigned char*)lpoutput;
	} else
	{
		result =  (unsigned char*)malloc(16);
	}
	MD4_CTX hash;
	MD4_INIT(&hash);
	MD4_UPDATE(&hash,data,(unsigned long)len);
	MD4_FINAL(result,&hash);
	return(result);
}

char* encoders::GetMD4TextHash(char *lpoutput, const char* data, size_t len)
{
	unsigned char md4sum[16];
	unsigned char *result;
	if (lpoutput)
	{
		result = (unsigned char*)lpoutput;
	} else
	{
		result =  (unsigned char*)malloc(16*2+1);
	}
	MD4_CTX hash;
	#undef a
	#define a md4sum

	MD4_INIT(&hash);
	MD4_UPDATE(&hash,data,(unsigned long)len);
	MD4_FINAL(md4sum,&hash);
	snprintf((char *)result,sizeof(md4sum)*2+1,
	 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	 a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
	 a[8], a[9], a[10],a[11],a[12],a[13],a[14],a[15]);
	//result[32]='\0';
	return((char*)result);
}

unsigned char* encoders::GetMD5BinaryHash(char *lpoutput, const char* data, size_t len)
{
	unsigned char *result ;
	if (lpoutput)
	{
		result = (unsigned char*)lpoutput;
	} else
	{
		result =  (unsigned char*)malloc(16);
	}
	MD5_CTX hash;
	MD5_INIT(&hash);
	MD5_UPDATE(&hash,data,(unsigned long)len);
	MD5_FINAL(result,&hash);
	return(result);
}

char* encoders::GetMD5TextHashA(char *lpoutput, const char* data, size_t len)
{
	unsigned char md5sum[16];
	unsigned char *result;
	if (lpoutput)
	{
		result = (unsigned char*)lpoutput;
	} else
	{
		result =  (unsigned char*)malloc(16*2+1);
	}

	MD5_CTX hash;
	#undef a
	#define a md5sum

	MD5_INIT(&hash);
	MD5_UPDATE(&hash,data,(unsigned long)len);
	MD5_FINAL(md5sum,&hash);
	snprintf((char *)result,sizeof(md5sum)*2+1,
	 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	 a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
	 a[8], a[9], a[10],a[11],a[12],a[13],a[14],a[15]);
	//result[32]='\0';
	return((char*)result);
}

/******************************************************************************/
#ifdef UNICODE
HTTPCHAR* encoders::GetMD5TextHashW(HTTPCHAR *lpoutputW, const HTTPCHAR* dataW, size_t len)
{
	
	char *data = (char*)malloc(len+1);
	char result[32+1];
	WideCharToMultiByte(CP_ACP, 0, dataW, len, data, len, NULL, NULL);
	GetMD5TextHashA(result,data,len);
	free(data);
	MultiByteToWideChar(CP_ACP, 0, result, 32, lpoutputW, 32);
	return(lpoutputW);
}
#endif
/******************************************************************************/
unsigned char* encoders::GetSHA1BinaryHash(char *lpoutput, const char* data, size_t len)
{
	unsigned char *result;
	if (lpoutput)
	{
		result = (unsigned char*)lpoutput;
	} else {
		result =  (unsigned char*)malloc(20);
	}
	SHA_CTX hash;
	SHA1_INIT(&hash);
	SHA1_UPDATE(&hash,data,(unsigned long)len);
	SHA1_FINAL(result,&hash);
	return(result);
}

char* encoders::GetSHA1TextHash(char *lpoutput, const char* data, size_t len)
{
	unsigned char sha1sum[20];
	unsigned char *result;
	if (lpoutput)
	{
		result = (unsigned char*)lpoutput;
	} else
	{
		result =  (unsigned char*)malloc(20*2+1);
	}
	SHA_CTX hash;
	#undef a
	#define a sha1sum

	SHA1_INIT(&hash);
	SHA1_UPDATE(&hash,data,(unsigned long)len);
	SHA1_FINAL(sha1sum,&hash);
	snprintf((char *)result,sizeof(sha1sum)*2+1,
	 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	 a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
	 a[8], a[9], a[10],a[11],a[12],a[13],a[14],a[15],
	 a[16], a[17], a[18], a[19], a[20] );
	return((char*)result);
}


HTTPCHAR *encoders::CreateDigestAuth(HTTPCSTR AuthenticationHeader, HTTPCSTR lpUsername, HTTPCSTR lpPassword, HTTPCSTR method,HTTPCSTR uri, int counter)
{
	/*
AuthenticationHeader is supoused to be in the following format:
realm="testrealm@host.com",qop="auth,auth-int",nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",opaque="5ccc069c403ebaf9f0171e9517f40e41"
//char test[]="WWW-Authenticate: Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
//char test[]="realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
*/
HTTPCHAR *realm=NULL;
HTTPCHAR *nonce=NULL;
HTTPCHAR *opaque=NULL;
HTTPCHAR *domain=NULL;
HTTPCHAR *algorithm=NULL;
HTTPCHAR *qop = NULL;

HTTPCHAR *trozo;
HTTPCHAR buffer[1024];

//response data
HTTPCHAR HAI[32+1];
HTTPCHAR HAII[32+1];
HTTPCHAR response[32+1];
HTTPCHAR data[1024];
HTTPCHAR tmp[1024];
unsigned int cnonceI;
unsigned int cnonceII;
unsigned int cnonceIII;
unsigned int cnonceIV;
HTTPCHAR cnonce[32+1];
HTTPCHAR *resultado;
int qopdefined =0;

if (!AuthenticationHeader) return (NULL);
if (_tcslen(AuthenticationHeader)>1024-1) {
	#ifdef _DBG_
	printf("[*] WARNING: POSSIBLE BUFFER OVERFLOW ON REMOTE AUTHENTICATON HEADER\n%s\n",AuthenticationHeader);
	#endif
 	return(NULL);
}
 _tcsncpy(buffer,AuthenticationHeader,1024-1);

 trozo=_tcstok(buffer,_T(","));
 while (trozo !=NULL)
 {
	 while (trozo[0]==' ') trozo++;

	 if (_tcsncicmp(trozo,_T("realm=\""),7)==0) {
		 realm=_tcsdup(trozo+7);
		 realm[_tcslen(realm)-1]=0;
	 }   else
	 if (_tcsncicmp(trozo,_T("nonce=\""),7)==0) {
		 nonce=_tcsdup(trozo+7);
		 nonce[_tcslen(nonce)-1]=0;
	 }   else
	 if (_tcsncicmp(trozo,_T("opaque=\""),8)==0) {
		 opaque=_tcsdup(trozo+8);
		 opaque[_tcslen(opaque)-1]=0;
	 } else
	 if (_tcsncicmp(trozo,_T("domain=\""),8)==0) {
		 domain=_tcsdup(trozo+8);
		 domain[_tcslen(domain)-1]=0;
		//free(domain); //Unused :?
	 } else
	 if (_tcsncicmp(trozo,_T("algorithm=\""),11)==0) {
		 algorithm=_tcsdup(trozo+11);
		 algorithm[_tcslen(algorithm)-1]=0;
	 } else
	 if (_tcsncicmp(trozo,_T("algorithm="),10)==0) {
		 algorithm=_tcsdup(trozo+10);
	 } else
	 if (_tcsncicmp(trozo,_T("qop=\""),5)==0) {
		 qop=_tcsdup(trozo+5);
		 qop[_tcslen(qop)-1]=0;
	 }


	 trozo=_tcstok(NULL,_T(","));
 }
 if ( (!realm) || (!nonce)  )
 {
		 if (realm) free(realm);
		 if (nonce) free(nonce);
		 if (opaque)  free(opaque);
		 if (domain) free(domain);
		 if (algorithm) free(algorithm);
		 if (qop) free(qop);
   //MessageBox( NULL, AuthenticationHeader, "AUTH DIGEST FAILED - Unable to parse realm+opaque+nonce", MB_OK|MB_ICONINFORMATION );
	return(NULL);
 }


srand ( (unsigned int) time(NULL) );
cnonceI=rand()*rand();
cnonceII=rand()*rand();
cnonceIII=rand()*rand();
cnonceIV=rand()*rand();
memset(data,0,sizeof(data));
_stprintf(cnonce,_T("%8.8X%8.8X%8.8X%8.8X"),cnonceI,cnonceII,cnonceIII,cnonceIV);

_sntprintf(tmp,sizeof(tmp),_T("Authorization: Digest username=\"%s\", "),lpUsername);
_tcsncpy(data,tmp,sizeof(data)/sizeof(HTTPCHAR)-1);

_sntprintf(tmp,sizeof(tmp),_T("realm=\"%s\", "),realm);
_tcsncat(data,tmp,sizeof(data)/sizeof(HTTPCHAR)-_tcslen(data)-1);

_sntprintf(tmp,sizeof(tmp),_T("nonce=\"%s\", "),nonce);
_tcsncat(data,tmp,sizeof(data)/sizeof(HTTPCHAR)-_tcslen(data)-1);

_sntprintf(tmp,sizeof(tmp),_T("uri=\"%s\", "),uri);
_tcsncat(data,tmp,sizeof(data)/sizeof(HTTPCHAR)-_tcslen(data)-1);

if (algorithm) _tcsncat(data,_T("algorithm=MD5, "),sizeof(data)/sizeof(HTTPCHAR)-_tcslen(data)-1);

_sntprintf(tmp,sizeof(tmp),_T("%s:%s:%s"),lpUsername,realm,lpPassword);
//Getmd5Hash(tmp,(int) strlen(tmp),(unsigned char*)&HAI[0]);
GetMD5TextHash((HTTPCHAR*)&HAI[0],tmp,(int) _tcslen(tmp));
//printf("HA1: %s - %s\n",tmp,HAI);

	if (qop)
	{
		if ( (_tcscmp(qop,_T("auth"))==0) || (_tcsnccmp(qop,_T("auth,"),5)==0))
			qopdefined =1;
		else if (_tcscmp(qop,_T("auth-int"))==0)
			qopdefined = 2;
	}

	if (qopdefined==2) { //TODO: FIX
		HTTPCHAR entityBody[]=_T("");
		_sntprintf(tmp,sizeof(tmp),_T("%s:%s:%s"),method,uri,entityBody);
	} else
		_sntprintf(tmp,sizeof(tmp),_T("%s:%s"),method,uri);
		//Getmd5Hash(tmp,(int) strlen(tmp),(unsigned char*)&HAII);
		GetMD5TextHash((HTTPCHAR*)&HAII,tmp,(int) _tcslen(tmp));
//	printf("HA2: %s - %s\n",tmp,HAII);


	if (qopdefined)    /* quality of protection */
	{
		if (qopdefined==2)
		{
			_sntprintf(tmp,sizeof(tmp),_T("%s:%s:%8.8x:%s:%s:%s"),HAI,nonce,counter+1,cnonce,_T("auth-int"),HAII);
		} else
		{
			_sntprintf(tmp,sizeof(tmp),_T("%s:%s:%8.8x:%s:%s:%s"),HAI,nonce,counter+1,cnonce,_T("auth"),HAII);
		}
	} else
	{
		_sntprintf(tmp,sizeof(tmp),_T("%s:%s:%s"),HAI,nonce,HAII);
	}
	//Getmd5Hash(tmp,(int) strlen(tmp),(unsigned char*)&response);
	GetMD5TextHash(&response[0],tmp,(int) _tcslen(tmp));

//	printf("Calculado3: %s - %s\n",tmp,response);


	_sntprintf(tmp,sizeof(tmp),_T("response=\"%s\", "),response);
	_tcsncat(data,tmp,sizeof(data)/sizeof(HTTPCHAR)-_tcslen(data)-1);

	if (opaque) {
		_sntprintf(tmp,sizeof(tmp),_T("opaque=\"%s\", "),opaque);
		_tcsncat(data,tmp,sizeof(data)/sizeof(HTTPCHAR)-_tcslen(data)-1);
	}

	if (qopdefined==1) {
		_tcsncat(data,_T("qop=\"auth\", "),sizeof(data)/sizeof(HTTPCHAR)-_tcslen(data)-1);
	} else if (qopdefined==2) {
		_tcsncat(data,_T("qop=\"auth-int\", "),sizeof(data)/sizeof(HTTPCHAR)-_tcslen(data)-1);
	}

	_sntprintf(tmp,sizeof(tmp),_T("nc=%8.8x, "),counter+1);
	_tcsncat(data,tmp,sizeof(data)/sizeof(HTTPCHAR)-_tcslen(data)-1);

	_sntprintf(tmp,sizeof(tmp)/sizeof(HTTPCHAR),_T("cnonce=\"%s\"\r\n"),cnonce);
	_tcsncat(data,tmp,sizeof(data)/sizeof(HTTPCHAR)-_tcslen(data)-1);


	resultado=_tcsdup(data);

	free(opaque);
	free(nonce);
	free(realm);
	if (algorithm)
	{
		free(algorithm);
	}
	if (domain)
	{
		free(domain) ;
	}
	if (qop) {
		free(qop);
	}

	return(resultado);
}

