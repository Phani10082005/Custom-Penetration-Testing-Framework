import socket
import sys
from concurrent.futures import ThreadPoolExecutor

SOCKET_TIMEOUT = 0.5
MAX_WORKERS = 50

def check_port(target_ip, port):
    """
    Attempts to establish a TCP connection to the specified port on the target IP.
    Returns (port, True) if open, (port, False) otherwise.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT)
    
    try:
        result = s.connect_ex((target_ip, port))
        if result == 0:
            return port, True
        else:
            return port, False
            
    except Exception:
        return port, False
    finally:
        s.close()

def port_scanner(target_ip, start_port, end_port):
    """
    Runs the port scanning process using ThreadPoolExecutor.
    """
    print(f"[*] Scanning Target: {target_ip}")
    print(f"[*] Port Range: {start_port}-{end_port}")
    print("-" * 50)
    
    ports_to_scan = range(start_port, end_port + 1)
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_port = [executor.submit(check_port, target_ip, port) for port in ports_to_scan]
        for future in future_to_port:
            port, is_open = future.result()
            if is_open:
                print(f"[+] Port {port:<5} is OPEN")
                open_ports.append(port)
    print("-" * 50)
    if open_ports:
        print(f"[SUCCESS] Scan completed. Found {len(open_ports)} open ports.")
    else:
        print("[INFO] Scan completed. No open ports found in the specified range.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <target_ip_or_hostname> <port_range>")
        print("Example: python simple_port_scanner.py 127.0.0.1 1-100")
        sys.exit(1)

    target = sys.argv[1]
    ports = sys.argv[2]
    
    try:
        target_ip_resolved = socket.gethostbyname(target)
        start_port, end_port = map(int, ports.split('-'))
        port_scanner(target_ip_resolved, start_port, end_port)      
    except socket.gaierror:
        print(f"\n[ERROR] Hostname '{target}' could not be resolved.")
        sys.exit(1)
    except ValueError:
        print(f"\n[ERROR] Invalid port range format. Please use 'start-end' (e.g., '1-100').")
        sys.exit(1)