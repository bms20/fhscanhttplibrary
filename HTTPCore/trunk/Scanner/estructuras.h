#ifndef ESTRUCTURAS_H
#define ESTRUCTURAS_H

#include <stdio.h>

/*
class FHSCANCONFIG {
	int ProxyInstance;
	int ManualRequest;
	int NoBruteforce;
	int VerboseMode;
	int nlogins;
	USERLIST *users;

public:

};
*/


struct _ports {
   int port;
   int ssl;
};

//hosts que no procesaremos
struct  _ignore {
   int status;
   HTTPCHAR server[200];
};

//Autenticacion de routers fuera del directorio raiz
struct _fakeauth {
   unsigned int	 status;
   HTTPCHAR  server[200];
   HTTPCHAR  authurl[200];
   HTTPCHAR  method[10]; //GET |POST
   HTTPCHAR  postdata[200];
};
typedef struct _logins {
	HTTPCHAR user[40];
} USERLOGIN;

//resultado de una peticion http


typedef struct _UserPass{
   HTTPCHAR UserName[50];
   HTTPCHAR Password[50];
} USERLIST;
//
//char *GetHeaderValue(HTTPSession* data, char  *Header) ;
///char *GetValue(HTTPCSTR lpBuffer);

//información de un router que soporta auth por webform
struct _webform {
   HTTPCHAR  model[200];       //Fake version
   unsigned int status;            //codigo de error de la página principal
   HTTPCHAR  server[200]; //banner del servidor Web
   HTTPCHAR  matchstring[200]; //string de la peticion con la que machear los resultados.
   HTTPCHAR  ValidateImage[200];
   HTTPCHAR  authurl[200];
   HTTPCHAR  authmethod[10];
   HTTPCHAR  authform[1024];
   int   requireloginandpass;
   HTTPCHAR  validauthstring[200];
   HTTPCHAR  validauthstringalt[200];
   HTTPCHAR  invalidauthstring[200];
   HTTPCHAR  invalidauthstringalt[200]; 
   HTTPCHAR  AdditionalHeader[200];
   int   UpdateCookie;
   HTTPCHAR  InitialCookieURL[200];
   HTTPCHAR  ValidateAlternativeurl[200];
   HTTPCHAR LoadAdditionalUrl[200];
   HTTPCHAR ReconnectOnMatch[200];
};

//vulnerability list

typedef struct _vulnerability_match
{
   HTTPCHAR Validatestring[200][200];
   HTTPCHAR Ignorestring[200];
   HTTPCHAR description[200];
   int  nstrings;
   }MATCH, *PMATCH;

typedef struct _vulnerability_list {
   HTTPCHAR  vulnerability[200];
   unsigned int status;
   HTTPCHAR server[200];
   HTTPCHAR  url[200];
   HTTPCHAR Ignoresignature[200];

   int nMatch;
   PMATCH Match;
   
} VLIST, *PVLIST;

#endif
