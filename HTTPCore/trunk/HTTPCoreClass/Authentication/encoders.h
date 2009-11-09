#ifndef __HTTP_ENCODERS__
#define __HTTP_ENCODERS__
#include "../build.h"
#include "../SSLModule.h"

class encoders : public SSLModule
{
public:
	encoders();
	~encoders();
	char* decodebase64(char *output, const char *input);
	char* encodebase64(char *output, const char *input, unsigned int len);	
	char *CreateDigestAuth(char *AuthenticationHeader, const char *lpUsername, const char *lpPassword, const char *method,const char *uri, int counter);
	unsigned char* GetMD2BinaryHash(char *output, const char *data, unsigned int len);
	char* GetMD2TextHash(char *output, const char *data, unsigned int len);
	unsigned char* GetMD4BinaryHash(char *output, const char *data, unsigned int len);
	char* GetMD4TextHash(char *output, const char *data, unsigned int len);
	unsigned char* GetMD5BinaryHash(char *output, const char *data, unsigned int len);
	char* GetMD5TextHash(char *output, const char *data, unsigned int len);
	unsigned char* GetSHA1BinaryHash(char *output, const char *data, unsigned int len);
	char* GetSHA1TextHash(char *output, const char *data, unsigned int len);

};

#endif