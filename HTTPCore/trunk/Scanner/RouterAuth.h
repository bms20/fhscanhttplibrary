#ifndef __ROUTERAUTH_H
#define __ROUTERAUTH_H




HTTPSession* CheckRouterAuth(HTTPAPI *api,HTTPHANDLE HTTPHandle,HTTPSession* data,int nRouterAuth, struct _fakeauth *AuthData,int nUsers, USERLIST *userpass);

#endif
