using System;
using System.Runtime.InteropServices;
using System.ServiceProcess; // Required to check service status
using System.Threading;

namespace EtwStartWebClient
{
    class Program
    {
        // ETW Provider GUID for WebClient Trigger
        private static Guid WebClientGuid = new Guid(0x22B6D684, 0xFA63, 0x4578, 0x87, 0xC9, 0xEF, 0xFC, 0xBE, 0x66, 0x43, 0xC7);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern uint EventRegister(ref Guid guid, IntPtr callback, IntPtr context, ref long handle);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern uint EventWrite(long handle, ref EVENT_DESCRIPTOR descriptor, uint count, IntPtr data);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern uint EventUnregister(long handle);

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public struct EVENT_DESCRIPTOR
        {
            [FieldOffset(0)] public ushort Id;
            [FieldOffset(2)] public byte Version;
            [FieldOffset(3)] public byte Channel;
            [FieldOffset(4)] public byte Level;
            [FieldOffset(5)] public byte Opcode;
            [FieldOffset(6)] public ushort Task;
            [FieldOffset(8)] public long Keyword;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Attempting to trigger WebClient service...");
            
            if (TriggerWebClient())
            {
                Console.WriteLine("[+] Trigger event sent successfully.");
                Console.WriteLine("[*] Waiting 3 seconds for service to start...");
                Thread.Sleep(3000); // Give SCM time to react
                VerifyServiceStatus();
            }
            else
            {
                Console.WriteLine("[-] Failed to register/send ETW event.");
            }
        }

        static bool TriggerWebClient()
        {
            long handle = 0;
            if (EventRegister(ref WebClientGuid, IntPtr.Zero, IntPtr.Zero, ref handle) == 0)
            {
                EVENT_DESCRIPTOR desc = new EVENT_DESCRIPTOR { Id = 1, Level = 4 };
                uint result = EventWrite(handle, ref desc, 0, IntPtr.Zero);
                EventUnregister(handle);
                return result == 0;
            }
            return false;
        }

        static void VerifyServiceStatus()
        {
            try
            {
                ServiceController sc = new ServiceController("WebClient");
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    Console.WriteLine("[!] SUCCESS: WebClient Service is now RUNNING.");
                }
                else
                {
                    Console.WriteLine("[X] FAILURE: Service is " + sc.Status.ToString() + ". (It might be disabled or not installed).");
                }
            }
            catch (Exception)
            {
                Console.WriteLine("[X] ERROR: Could not find the WebClient service on this machine.");
            }
        }
    }
}
