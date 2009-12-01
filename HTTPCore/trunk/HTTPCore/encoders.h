#ifndef __HTTP_ENCODERS__
#define __HTTP_ENCODERS__
#include "SSLModule.h"

class encoders : public SSLModule
{
public:
	encoders();
	~encoders();
	char* decodebase64(char *output, HTTPCSTR input);
	char* encodebase64(char *output, HTTPCSTR input, size_t len);	
	char *CreateDigestAuth(char *AuthenticationHeader, HTTPCSTR lpUsername, HTTPCSTR lpPassword, HTTPCSTR method,HTTPCSTR uri, int counter);
	char *GetNTLMBase64Packet1(char*destination);
	char *GetNTLMBase64Packet3(char*destination, const char* NTLMresponse, HTTPCSTR lpUsername, const char* lpPassword);
	unsigned char* GetMD2BinaryHash(char *output, HTTPCSTR data, size_t len);
	char* GetMD2TextHash(char *output, HTTPCSTR data, size_t len);
	unsigned char* GetMD4BinaryHash(char *output, HTTPCSTR data, size_t len);
	char* GetMD4TextHash(char *output, HTTPCSTR data, size_t len);
	unsigned char* GetMD5BinaryHash(char *output, HTTPCSTR data, size_t len);
	char* GetMD5TextHash(char *output, HTTPCSTR data, size_t len);
	unsigned char* GetSHA1BinaryHash(char *output, HTTPCSTR data, size_t len);
	char* GetSHA1TextHash(char *output, HTTPCSTR data, size_t len);

};

#endif
