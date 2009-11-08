#ifndef __HTTP_ENCODERS__
#define __HTTP_ENCODERS__
#include "../SSLModule.h"

class encoders : public SSLModule{

public:
	encoders();
	~encoders();
	char* decodebase64(char *input);
	char* encodebase64(char *input, unsigned int len);
	char *CreateDigestAuth(char *AuthenticationHeader, const char *lpUsername, const char *lpPassword, const char *method,const char *uri, int counter);
	unsigned char* GetMD2BinaryHash(const unsigned char *data, unsigned int len);
	unsigned char* GetMD2TextHash(const unsigned char *data, unsigned int len);
	unsigned char* GetMD4BinaryHash(const unsigned char *data, unsigned int len);
	unsigned char* GetMD4TextHash(const unsigned char *data, unsigned int len);
	unsigned char* GetMD5BinaryHash(const unsigned char *data, unsigned int len);
	unsigned char* GetMD5TextHash(const unsigned char *data, unsigned int len);
	unsigned char* GetSHA1BinaryHash(const unsigned char *data, unsigned int len);
	unsigned char* GetSHA1TextHash(const unsigned char *data, unsigned int len);

};

#endif