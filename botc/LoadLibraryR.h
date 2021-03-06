#ifndef _REFLECTIVEDLLINJECTION_LOADLIBRARYR_H
#define _REFLECTIVEDLLINJECTION_LOADLIBRARYR_H

#include "ReflectiveDLLInjection.h"
#ifdef __MINGW32__
#define __try
#define __except(x) if(0)
#endif

DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer );

HMODULE WINAPI LoadLibraryR( LPVOID lpBuffer, DWORD dwLength );

HANDLE WINAPI LoadRemoteLibraryR( HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter );

#endif

