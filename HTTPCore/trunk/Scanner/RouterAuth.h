#ifndef __ROUTERAUTH_H
#define __ROUTERAUTH_H




PREQUEST CheckRouterAuth(HTTPAPI *api,HTTPHANDLE HTTPHandle,PREQUEST data,int nRouterAuth, struct _fakeauth *AuthData,int nUsers, USERLIST *userpass);

#endif
