#include "encoders.h"
#include "../build.h"


encoders::encoders()
{

}

encoders::~encoders()
{
}


/*************************************************************************************/

char* encoders::decodebase64(char *lpoutput, const char *input)
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

char* encoders::encodebase64(char *lpoutput, const char *input, unsigned int inputlen)
{
	if (inputlen)
	{
		BIO * b642  = BIO_NEW(BIO_F_BASE64());
		BIO * bmem2 = BIO_NEW(BIO_S_MEM());
		b642 = BIO_PUSH(b642, bmem2);
		BIO_WRITE(b642, input, inputlen);
		BIO_FLUSH(b642);
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

unsigned char* encoders::GetMD2BinaryHash(char *lpoutput, const char *data, unsigned int len)
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
	MD2_UPDATE(&hash,data,len);
	MD2_FINAL(output,&hash);
	return(output);
}

char* encoders::GetMD2TextHash(char *lpoutput, const char *data, unsigned int len)
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
	MD2_UPDATE(&hash,data,len);
	MD2_FINAL(md2sum,&hash);
	snprintf((char *)result,sizeof(md2sum)*2+1,
	 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	 a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
	 a[8], a[9], a[10],a[11],a[12],a[13],a[14],a[15]);
	//result[32]='\0';
	return((char*)result);
}

unsigned char* encoders::GetMD4BinaryHash(char *lpoutput, const char *data, unsigned int len)
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
	MD4_UPDATE(&hash,data,len);
	MD4_FINAL(result,&hash);
	return(result);
}

char* encoders::GetMD4TextHash(char *lpoutput, const char *data, unsigned int len)
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
	MD4_UPDATE(&hash,data,len);
	MD4_FINAL(md4sum,&hash);
	snprintf((char *)result,sizeof(md4sum)*2+1,
	 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	 a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
	 a[8], a[9], a[10],a[11],a[12],a[13],a[14],a[15]);
	//result[32]='\0';
	return((char*)result);
}

unsigned char* encoders::GetMD5BinaryHash(char *lpoutput, const char *data, unsigned int len)
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
	MD5_UPDATE(&hash,data,len);
	MD5_FINAL(result,&hash);
	return(result);
}

char* encoders::GetMD5TextHash(char *lpoutput, const char *data, unsigned int len)
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
	MD5_UPDATE(&hash,data,len);
	MD5_FINAL(md5sum,&hash);
	snprintf((char *)result,sizeof(md5sum)*2+1,
	 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	 a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
	 a[8], a[9], a[10],a[11],a[12],a[13],a[14],a[15]);
	//result[32]='\0';
	return((char*)result);
}

/******************************************************************************/

unsigned char* encoders::GetSHA1BinaryHash(char *lpoutput, const char *data, unsigned int len)
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
	SHA1_UPDATE(&hash,data,len);
	SHA1_FINAL(result,&hash);
	return(result);
}

char* encoders::GetSHA1TextHash(char *lpoutput, const char *data, unsigned int len)
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
	SHA1_UPDATE(&hash,data,len);
	SHA1_FINAL(sha1sum,&hash);
	snprintf((char *)result,sizeof(sha1sum)*2+1,
	 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	 a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
	 a[8], a[9], a[10],a[11],a[12],a[13],a[14],a[15],
	 a[16], a[17], a[18], a[19], a[20] );
	return((char*)result);
}


char *encoders::CreateDigestAuth(char *AuthenticationHeader, const char *lpUsername, const char *lpPassword, const char *method,const char *uri, int counter)
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
//Getmd5Hash(tmp,(int) strlen(tmp),(unsigned char*)&HAI[0]);
GetMD5TextHash((char*)&HAI[0],tmp,(int) strlen(tmp));
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
		//Getmd5Hash(tmp,(int) strlen(tmp),(unsigned char*)&HAII);
		GetMD5TextHash((char*)&HAII,tmp,(int) strlen(tmp));
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
	//Getmd5Hash(tmp,(int) strlen(tmp),(unsigned char*)&response);
	GetMD5TextHash(&response[0],tmp,(int) strlen(tmp));

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
