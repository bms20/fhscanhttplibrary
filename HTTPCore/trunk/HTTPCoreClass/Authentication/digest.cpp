/* http://www.ietf.org/rfc/rfc2617.txt*/

/*
*  Fast HTTP AUTH SCANNER - v0.9r2
*
*  Digest Authentication Module for Fscan
*
* References: http://tools.ietf.org/html/rfc2617
* References: http://en.wikipedia.org/wiki/Digest_access_authentication
*/

//#include "md5.h"
#include "../Build.h"
#include "digest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


char *CreateDigestAuth(char *AuthenticationHeader, const char *lpUsername, const char *lpPassword, const char *method,const char *uri, int counter)
{
	/*
AuthenticationHeader is supoused to be in the following format:
realm="testrealm@host.com",qop="auth,auth-int",nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",opaque="5ccc069c403ebaf9f0171e9517f40e41"
//char test[]="WWW-Authenticate: Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
//char test[]="realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
*/
char *realm=NULL;
char *nonce=NULL;
char *opaque=NULL;
char *domain=NULL;
char *algorithm=NULL;
char *qop = NULL;

char *trozo;
char buffer[1024];

//response data
char HAI[32+1];
char HAII[32+1];
char response[32+1];
char data[1024];
char tmp[1024];
unsigned int cnonceI;
unsigned int cnonceII;
unsigned int cnonceIII;
unsigned int cnonceIV;
char cnonce[32+1];
char *resultado;
int qopdefined =0;

if (!AuthenticationHeader) return (NULL);
if (strlen(AuthenticationHeader)>sizeof(buffer)-1) {
	#ifdef _DBG_
	printf("[*] WARNING: POSSIBLE BUFFER OVERFLOW ON REMOTE AUTHENTICATON HEADER\n%s\n",AuthenticationHeader);
	#endif
 	return(NULL);
}
 strncpy(buffer,AuthenticationHeader,sizeof(buffer)-1);

 trozo=strtok(buffer,",");
 while (trozo !=NULL)
 {
	 while (trozo[0]==' ') trozo++;

	 if (strnicmp(trozo,"realm=\"",7)==0) {
		 realm=strdup(trozo+7);
		 realm[strlen(realm)-1]='\0';
	 }   else
	 if (strnicmp(trozo,"nonce=\"",7)==0) {
		 nonce=strdup(trozo+7);
		 nonce[strlen(nonce)-1]='\0';
	 }   else
	 if (strnicmp(trozo,"opaque=\"",8)==0) {
		 opaque=strdup(trozo+8);
		 opaque[strlen(opaque)-1]='\0';
	 } else
	 if (strnicmp(trozo,"domain=\"",8)==0) {
		 domain=strdup(trozo+8);
		 domain[strlen(domain)-1]='\0';
		//free(domain); //Unused :?
	 } else
	 if (strnicmp(trozo,"algorithm=\"",11)==0) {
		 algorithm=strdup(trozo+11);
		 algorithm[strlen(algorithm)-1]='\0';
	 } else
	 if (strnicmp(trozo,"algorithm=",10)==0) {
		 algorithm=strdup(trozo+10);
	 } else
	 if (strnicmp(trozo,"qop=\"",5)==0) {
		 qop=strdup(trozo+5);
		 qop[strlen(qop)-1]='\0';
	 }


	 trozo=strtok(NULL,",");
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
memset(data,'\0',sizeof(data));
sprintf(cnonce,"%8.8X%8.8X%8.8X%8.8X",cnonceI,cnonceII,cnonceIII,cnonceIV);

snprintf(tmp,sizeof(tmp),"Authorization: Digest username=\"%s\", ",lpUsername);
strncpy(data,tmp,sizeof(data)-1);

snprintf(tmp,sizeof(tmp),"realm=\"%s\", ",realm);
strncat(data,tmp,sizeof(data)-strlen(data)-1);

snprintf(tmp,sizeof(tmp),"nonce=\"%s\", ",nonce);
strncat(data,tmp,sizeof(data)-strlen(data)-1);

snprintf(tmp,sizeof(tmp),"uri=\"%s\", ",uri);
strncat(data,tmp,sizeof(data)-strlen(data)-1);

if (algorithm) strncat(data,"algorithm=MD5, ",sizeof(data)-strlen(data)-1);

snprintf(tmp,sizeof(tmp),"%s:%s:%s",lpUsername,realm,lpPassword);
Getmd5Hash(tmp,(int) strlen(tmp),(unsigned char*)&HAI[0]);
//printf("HA1: %s - %s\n",tmp,HAI);

	if (qop)
	{
		if ( (strcmp(qop,"auth")==0) || (strncmp(qop,"auth,",5)==0))
			qopdefined =1;
		else if (strcmp(qop,"auth-int")==0)
			qopdefined = 2;
	}

	if (qopdefined==2) { //TODO: FIX
		char entityBody[]="";
		snprintf(tmp,sizeof(tmp),"%s:%s:%s",method,uri,entityBody);
	} else
		snprintf(tmp,sizeof(tmp),"%s:%s",method,uri);
		Getmd5Hash(tmp,(int) strlen(tmp),(unsigned char*)&HAII);
//	printf("HA2: %s - %s\n",tmp,HAII);


	if (qopdefined)    /* quality of protection */
	{
		if (qopdefined==2)
		{
			snprintf(tmp,sizeof(tmp),"%s:%s:%8.8x:%s:%s:%s",HAI,nonce,counter+1,cnonce,"auth-int",HAII);
		} else
		{
			snprintf(tmp,sizeof(tmp),"%s:%s:%8.8x:%s:%s:%s",HAI,nonce,counter+1,cnonce,"auth",HAII);
		}
	} else
	{
		snprintf(tmp,sizeof(tmp),"%s:%s:%s",HAI,nonce,HAII);
	}
	Getmd5Hash(tmp,(int) strlen(tmp),(unsigned char*)&response);

//	printf("Calculado3: %s - %s\n",tmp,response);


	snprintf(tmp,sizeof(tmp),"response=\"%s\", ",response);
	strncat(data,tmp,sizeof(data)-strlen(data)-1);

	if (opaque) {
		snprintf(tmp,sizeof(tmp),"opaque=\"%s\", ",opaque);
		strncat(data,tmp,sizeof(data)-strlen(data)-1);
	}

	if (qopdefined==1) {
		strncat(data,"qop=\"auth\", ",sizeof(data)-strlen(data)-1);
	} else if (qopdefined==2) {
		strncat(data,"qop=\"auth-int\", ",sizeof(data)-strlen(data)-1);
	}

	snprintf(tmp,sizeof(tmp),"nc=%8.8x, ",counter+1);
	strncat(data,tmp,sizeof(data)-strlen(data)-1);

	snprintf(tmp,sizeof(tmp),"cnonce=\"%s\"\r\n",cnonce);
	strncat(data,tmp,sizeof(data)-strlen(data)-1);


	resultado=strdup(data);

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
