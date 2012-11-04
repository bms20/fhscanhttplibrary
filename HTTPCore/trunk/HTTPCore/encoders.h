#ifndef __HTTP_ENCODERS__
#define __HTTP_ENCODERS__
#include "SSLModule.h"

#ifdef UNICODE
#define decodebase64 decodebase64W
#define encodebase64 encodebase64W
#define GetMD5TextHash GetMD5TextHashW
#else
#define decodebase64 decodebase64A
#define encodebase64 encodebase64A
#define GetMD5TextHash GetMD5TextHashA
#endif

class encoders : public SSLModule {
public:
	encoders();
	~encoders();
	char* decodebase64A(char *output, const char* input);
	char* encodebase64A(char *output, const char* input, size_t len);

#ifdef UNICODE
	HTTPCHAR* decodebase64W(HTTPCHAR *lpoutputW, const HTTPCHAR* inputW);
	HTTPCHAR* encodebase64W(HTTPCHAR *lpoutputW, HTTPCSTR inputW,
		size_t inputlen);
#endif

	HTTPCHAR *CreateDigestAuth(HTTPCSTR AuthenticationHeader,
		HTTPCSTR lpUsername, HTTPCSTR lpPassword, HTTPCSTR method, HTTPCSTR uri,
		int counter);
	HTTPCHAR* GetNTLMBase64Packet1(HTTPCHAR* destination);
	HTTPCHAR* GetNTLMBase64Packet3(HTTPCHAR*destination, HTTPCSTR NTLMresponse,
		HTTPCSTR lpUsername, HTTPCSTR lpPassword);
	unsigned char* GetMD2BinaryHash(char *output, const char* data, size_t len);
	char* GetMD2TextHash(char *output, const char* data, size_t len);
	unsigned char* GetMD4BinaryHash(char *output, const char* data, size_t len);
	char* GetMD4TextHash(char *output, const char* data, size_t len);
	unsigned char* GetMD5BinaryHash(char *output, const char* data, size_t len);
	char* GetMD5TextHashA(char *output, const char* data, size_t len);
#ifdef UNICODE
	HTTPCHAR* GetMD5TextHashW(HTTPCHAR *lpoutputW, const HTTPCHAR* dataW,
		size_t len);
#endif
	unsigned char* GetSHA1BinaryHash(char *output, const char* data,
		size_t len);
	char* GetSHA1TextHash(char *output, const char* data, size_t len);

};

#endif
