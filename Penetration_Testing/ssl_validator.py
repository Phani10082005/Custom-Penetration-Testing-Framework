import ssl
import socket
import sys
import time
from datetime import datetime
from OpenSSL import SSL, crypto

DEFAULT_PORT = 443 
SOCKET_TIMEOUT = 5

def check_ssl_vulnerability(target_host, target_port):
    """
    Connects to an HTTPS service, retrieves the certificate, and checks its validity.
    """
    context = ssl.create_default_context()
    context.check_hostname = True 
    context.verify_mode = ssl.CERT_REQUIRED
    
    print("-" * 60)
    print(f"[*] Validating SSL Certificate for: {target_host}:{target_port}")
    print("-" * 60)

    try:
        with socket.create_connection((target_host, target_port), timeout=SOCKET_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=target_host) as conn:
                cert_data = conn.getpeercert(True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
                not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
                not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                
                current_time = datetime.utcnow()
                expired_status = "EXPIRED/INVALID" if x509.has_expired() else "VALID"

                print(f"[+] Status: {expired_status}")
                print(f"[+] Subject: {x509.get_subject().CN}")
                print(f"[+] Issuer: {x509.get_issuer().CN}")
                print(f"[+] Valid From: {not_before} UTC")
                print(f"[+] Valid Until: {not_after} UTC")
                if x509.has_expired():
                    print(f"!!! VULNERABILITY FOUND: CERTIFICATE HAS EXPIRED (on {not_after})")
                else:
                    days_remaining = (not_after - current_time).days
                    print(f"[INFO] Certificate expiration date is valid. ({days_remaining} days remaining)")

    except ssl.SSLError as e:
        print(f"[ERROR] SSL/TLS Handshake Error: {e}")
        print("[INFO] This could indicate an incompatible TLS version or a self-signed certificate.")
    except socket.gaierror:
        print(f"[ERROR] Hostname '{target_host}' could not be resolved.")
    except socket.timeout:
        print(f"[ERROR] Connection timed out after {SOCKET_TIMEOUT} seconds.")
    except Exception as e:
        print(f"[ERROR] General Error during check: {type(e).__name__}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <hostname>")
        print("Example: python ssl_validator.py google.com")
        sys.exit(1)

    target_host = sys.argv[1]
    check_ssl_vulnerability(target_host, DEFAULT_PORT)