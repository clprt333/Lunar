#ifndef _REFLECTIVEDLLINJECTION_GETPROCADDRESSR_H
#define _REFLECTIVEDLLINJECTION_GETPROCADDRESSR_H
#include "ReflectiveDLLInjection.h"
#ifdef __MINGW32__
#define __try
#define __except(x) if(0)
#endif

FARPROC WINAPI GetProcAddressR( HANDLE hModule, LPCSTR lpProcName );
#endif

