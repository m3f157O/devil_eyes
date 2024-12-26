using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.AutomatedAnalysis;
using System.Collections;
using System.Text.RegularExpressions;
using System.Xml;
using System.Text.Json;




namespace SimpleKernelConsumer
{
 



    class Program
    {
        static string ComputeMd5Hash(string input)
        {
            // Create a new instance of MD5
            using (MD5 md5 = MD5.Create())
            {
                // Convert the input string to a byte array and compute the hash
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to a hexadecimal string
                StringBuilder hashBuilder = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    hashBuilder.Append(b.ToString("x2")); // "x2": hexadecimal representation, lower case
                }

                return hashBuilder.ToString();
            }
        }

        static void Main(string[] args)
        {
            string filePath = "example.txt";

            StreamWriter writer = new StreamWriter(filePath);



            List<string> registryHit = new List<string>();
            List<string> processStart = new List<string>();
            List<string> connection = new List<string>();
            List<string> fileCreated = new List<string>();
            Dictionary<string, string> filesOpened = new Dictionary<string, string>
            {

            };
            Dictionary<string, string> registry = new Dictionary<string, string>
            {
                { "Terminal Server Client","RDP Connected ipaddress"},
 { "Office","FIND OPENED DOCUMENTS"},
 { "MostRecentApplication","Meterpretr webcam_snap — can find which app used"},
 { "Classes","Classes"},
 { "Extensions","Google\\Chrome\\Extensions"},
 { "Installed Components","check rundll"},
 { "PackagedAppXDebug","wpa persistence"},
 { "Policies\\System ","uac check"},
 { "AlwaysInstallElevated","privesc check"},
 { "Security Packages","lsa pers"},
 { "RunMRU","persistence"},
 { "Shell Folders","persistence"},
 { "Services","services"},
 { "Tasks","schedtask"},
 { "PSEXESVC","new service"},
 { "Microsoft\\WindowsNT\\CurrentVersion\\Schedule\\TaskCache\\Tree","schedtask"},
 { "NTUSER\\Software\\Microsoft\\TerminalServer Client\\Servers","remote desktop"},
 { "HKCU\\Software\\SysInternals\\PsExec\\EulaAccepted","psexec"},
 { "Microsoft\\Wbem\\CIMOM","wmi malicious"},
 { "HKEY_*\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt","DLL LOADING IN LSASS"},
 { "CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPtr","DLL LOADING IN LSASS"},
 { "Software\\Microsoft\\Windows\\CurrentVersion\\Run","hklmrun"},
 { "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce","hklmrun"},
 { "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx","hklmrun"},
 { "\\SOFTWARE\\\\Microsoft\\\\Netsh","hklmrun"},
 { "Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler","hklmrun"},
 { "\\currentversion\\run","hklmrun"},
 { "CurrentVersion\\Winlogon\\Notify","hklmrun"},
 { "CurrentVersion\\Winlogon\\Shell","hklmrun"},
 { "CurrentVersion\\\\Winlogon\\\\VmApplet","hklmrun"},
 { "CurrentVersion\\\\Winlogon\\\\Userinit","hklmrun"},
 { "currentversion\\\\policies\\\\explorer\\\\run","hklmrun"},
 { "\\\\Classes\\\\htmlfile\\\\shell\\\\open\\\\command","hklmrun"},
 { "Explorer\\Shell Folders\\Common Startup","hklmrun"},
 { "Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options","hklmrun"},
 { "CurrentControlSet\\\\Control\\\\Lsa","hklmrun"},
 { "CurrentVersion\\\\SilentProcessExit","hklmrun"},
 { "CurrentControlSet\\\\Control\\\\Lsa\\\\OSConfig","hklmrun"},
                 { "\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\StartupApproved\\\\Run","persistence"},


            };
            Dictionary<int, string> processfilenames = new Dictionary<int, string>
            {

            };

            int[] registryOpenCheck = new int[50]; // All elements are automatically initialized to zero.
            int[] registrySetCheck = new int[50]; // All elements are automatically initialized to zero.
            int[] registryCreateCheck = new int[50]; // All elements are automatically initialized to zero.


            var regexList = new List<Regex>();
            foreach (var entry in registry)
            {
                string pattern = Regex.Escape(entry.Key); // Escape special characters
                regexList.Add(new Regex(pattern, RegexOptions.IgnoreCase));
            }
            int target = 0;
            if (args.Length < 1)
            {
                Console.WriteLine("give executable name -.-");
                return;
            }
            string targetFileName = args[0];

            string dest = "filedata.txt";

            FileStream fs = File.Create(dest);
            using (var session = new TraceEventSession(Environment.OSVersion.Version.Build >= 9200 ? "MyKernelSession" : KernelTraceEventParser.KernelSessionName))
            {
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP | KernelTraceEventParser.Keywords.Registry | KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.ImageLoad | KernelTraceEventParser.Keywords.FileIOInit |  KernelTraceEventParser.Keywords.FileIO );
                var parser = session.Source.Kernel;
        
                parser.RegistryCreate += e => {
                    if (processfilenames.TryGetValue(e.ProcessID, out string zzz))
                    {
                        foreach (var pattern in regexList)
                        {
                            // Compile the regex

                            // Perform the match
                            bool isMatch = pattern.IsMatch(e.KeyName);

                            // Output the result
                            if (isMatch && registryCreateCheck[regexList.IndexOf(pattern)].Equals(0))
                            {
                                ;
                                registryCreateCheck[regexList.IndexOf(pattern)] = 1;
                                var person = new
                                {
                                    source = "RegistryCreate",
                                    PID = e.ProcessID,
                                    name = e.ProcessName,
                                    time = $"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}",
                                    CommandLine = e.KeyName.Replace("\"", ""),

                                };

                                string jsonString = JsonSerializer.Serialize(person);

                                Console.WriteLine(jsonString);
                                //regexList.Remove(pattern);
                                //registryHit.Add(e.KeyName);

                            }
                        }
                    }
                };

                parser.RegistryOpen += e => {
                    if (processfilenames.TryGetValue(e.ProcessID, out string zzz))
                    {
                        foreach (var pattern in regexList)
                        {
                            // Compile the regex

                            // Perform the match
                            bool isMatch = pattern.IsMatch(e.KeyName);

                            // Output the result
                            if (isMatch && registryOpenCheck[regexList.IndexOf(pattern)].Equals(0))
                            {
                                var person = new
                                {
                                    source = "RegistryOpen",
                                    PID = e.ProcessID,
                                    name = e.ProcessName,
                                    time = $"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}",
                                    CommandLine = e.KeyName.Replace("\"", ""),

                                };

                                string jsonString = JsonSerializer.Serialize(person);

                                Console.WriteLine(jsonString); ;
                                registryOpenCheck[regexList.IndexOf(pattern)] = 1;
                                //regexList.Remove(pattern);
                                //registryHit.Add(e.KeyName);

                            }
                        }
                    }

                };


                parser.RegistrySetValue += e => {
                    if (processfilenames.TryGetValue(e.ProcessID, out string zzz))
                    {
                        foreach (var pattern in regexList)
                        {
                            // Compile the regex

                            // Perform the match
                            bool isMatch = pattern.IsMatch(e.KeyName);

                            // Output the result
                            if (isMatch && registrySetCheck[regexList.IndexOf(pattern)].Equals(0))
                            {
                                var person = new
                                {
                                    source = "RegistrySet",
                                    PID = e.ProcessID,
                                    name = e.ProcessName,
                                    time = $"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}",
                                    CommandLine = e.KeyName.Replace("\"", ""),

                                };

                                string jsonString = JsonSerializer.Serialize(person);

                                Console.WriteLine(jsonString); ;
                                registrySetCheck[regexList.IndexOf(pattern)] = 1;
                                //regexList.Remove(pattern);
                                //registryHit.Add(e.KeyName);

                            }

                        }
                    }
                };

       

                parser.UdpIpSend += e => {
                    //todo
                    if (processfilenames.TryGetValue(e.ProcessID, out string zzz))
                    {
                        
                        Console.WriteLine($"{e.EventName} {e.saddr} {e.sport} {e.dport} ({e.daddr}) ({e.ProcessID}) ({e.ProcessName})");
                        //tod
                    }
                };
                parser.UdpIpRecv += e => {
                    //todo
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    if (processfilenames.TryGetValue(e.ProcessID, out string zzz))
                    {
                        Console.WriteLine($"{e.EventName} {e.saddr} {e.sport} {e.dport} ({e.daddr}) ({e.ProcessID}) ({e.ProcessName})");
                        //tod
                    }                //tod
                };

                parser.TcpIpSend += e => {
                    //todo
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    if (processfilenames.TryGetValue(e.ProcessID, out string zzz))
                    {
                        

                        Console.WriteLine($"{{\"source\":\"{e.EventName}\", \"saddr\":\"{e.saddr}\", \"sport\":\"{e.sport}\", \"dport\":\"{e.dport}\", \"daddr\":\"{e.daddr}\", \"ProcessID\":{e.ProcessID}, \"FileName\":\"{e.ProcessName}\"}}");
                        //tod
                    }
                    //tod
                };
                parser.TcpIpRecv += e => {
                    //todo
                    Console.ForegroundColor = ConsoleColor.Magenta;

                    if (processfilenames.TryGetValue(e.ProcessID, out string zzz))
                    {
                        Console.WriteLine($"{{\"source\":\"{e.EventName}\", \"saddr\":\"{e.saddr}\", \"sport\":\"{e.sport}\", \"dport\":\"{e.dport}\", \"daddr\":\"{e.daddr}\", \"ProcessID\":{e.ProcessID}, \"FileName\":\"{e.ProcessName}\"}}");
                        //tod
                    }
    
                };


                parser.FileIOCreate += e => {
                    //todo

                    Console.ForegroundColor = ConsoleColor.Magenta;
                    if (processfilenames.TryGetValue(e.ProcessID, out string zzz)) {
                       

                            string processPath = "";
                            if (!filesOpened.TryGetValue(e.FileName, out string value))
                            {
                                try
                                {
                                    System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(e.ProcessID);


                                    filesOpened.Add(e.FileName, e.ProcessID.ToString() + e.ProcessName + e.FileName);
                                string info = $"{e.EventName} {e.ProcessName} {e.ProcessID} ({process.MainModule.FileName}) ({e.FileName})  ";
                                       //fs.Write(Encoding.UTF8.GetBytes(info), 0, info.Length);


                            }
                            catch (ArgumentException)
                                {
                                   // Console.WriteLine($"No process with PID {e.ProcessID} is running.");
                                }
                    }
                            


                        

                    }
                    //todo
                };
             
                parser.ProcessStart += e => {

                    Console.ForegroundColor = ConsoleColor.Green;
                    if(processfilenames.Count==0)
                    {
                        
                        if (e.ImageFileName.Equals(targetFileName))
                        {
                            processfilenames.Add(e.ProcessID, e.ProcessName + " " + e.ParentID);
                            if (e.ImageFileName.Equals(targetFileName))
                            {
                                var person = new
                                {
                                    source = "ProcessStart",
                                    PID = e.ProcessID,
                                    PPID = e.ParentID,
                                    name = e.ProcessName,
                                    time = $"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}",
                                    FileName = e.ImageFileName,
                                    CommandLine = e.CommandLine.Replace("\"", ""),

                                };

                                string jsonString = JsonSerializer.Serialize(person);

                                Console.WriteLine(jsonString);
                            }
                        }
                    }
                    else if (processfilenames.TryGetValue(e.ParentID, out string value))
                    {
                       
                        
                        {
                            processfilenames.Add(e.ProcessID, e.ProcessName+" "+e.ParentID);
                            var person = new
                            {
                                source = "ChildProcessStart",
                                PID = e.ProcessID,
                                PPID = e.ParentID,
                                name = e.ProcessName,
                                time = $"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}",
                                FileName = e.ImageFileName,
                                CommandLine = e.CommandLine.Replace("\"", ""),

                            };

                            string jsonString = JsonSerializer.Serialize(person);

                            Console.WriteLine(jsonString);
                        }
                    }
                    else
                    {
                        var person = new
                        {
                            source = "ProcessStartExternal",
                            PID = e.ProcessID,
                            PPID = e.ParentID,
                            name = e.ProcessName,
                            time = $"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}",
                            FileName = e.ImageFileName,
                            CommandLine = e.CommandLine.Replace("\"", ""),

                        };

                        string jsonString = JsonSerializer.Serialize(person);

                        Console.WriteLine(jsonString);
                    }
                    
                    




                };
                parser.ProcessStop += e => {
                    if (processfilenames.TryGetValue(e.ProcessID, out string value))
                    {
                                            Console.ForegroundColor = ConsoleColor.Red;

                        var person = new
                        {
                            source = "ProcessStop",
                            PID = e.ProcessID,
                            PPID = e.ParentID,
                            name = e.ProcessName,
                            time = $"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}",
                            FileName = e.ImageFileName,
                            CommandLine = e.CommandLine.Replace("\"", ""),

                        };

                        string jsonString = JsonSerializer.Serialize(person);

                        Console.WriteLine(jsonString);
                        processfilenames.Remove(e.ProcessID);
                    }
                };


                Task.Run(() => session.Source.Process());


                /*parser.ImageLoad += e => {
    Console.ForegroundColor = ConsoleColor.Yellow;

    //Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: Image Loaded: {e.FileName} into process {e.ProcessID} ({name}) Size=0x{e.ImageSize:X}");
};

parser.ImageUnload += e => {
    //Console.ForegroundColor = ConsoleColor.DarkYellow;
  //  Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: Image Unloaded: {e.FileName} from process {e.ProcessID} ({name})");
};
*/



                Thread.Sleep(TimeSpan.FromSeconds(999));    
            }

    
        }
        
    }
}