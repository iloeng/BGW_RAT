// CHAT.cpp : Defines the entry point for the DLL application.
//

#include "TextChat.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"user32.lib")

HMODULE m_DllModule = NULL;

BOOL APIENTRY _DllMain( HANDLE hModule,
                        DWORD  ul_reason_for_call,
                        LPVOID lpReserved
                      )
{
    m_DllModule = (HMODULE)hModule;
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL PluginMe(LPCTSTR lpszHost, UINT nPort, LPBYTE lparam)
{
    CClientSocket	socketClient;
    if (!socketClient.Connect(lpszHost, nPort))
        return -1;

    CTextChat	manager(&socketClient);
    socketClient.run_event_loop();

    return 0;
}

