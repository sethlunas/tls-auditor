import ssl
import socket

# simple HTTPS test server with deliberately weak cipher suite
# used exclusively for testing the auditor's weak cipher detection

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile="/app/nginx-weak/certs/cert.pem",
    keyfile="/app/nginx-weak/certs/key.pem"
)

# restrict to TLS 1.2 only so weak cipher negotiation actually happens
# TLS 1.3 has fixed strong ciphers that can't be overridden
context.maximum_version = ssl.TLSVersion.TLSv1_2
context.minimum_version = ssl.TLSVersion.TLSv1_2

# force a weak cipher; 3DES has no forward secrecy and is considered broken
context.set_ciphers("AES128-SHA")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 8443))
    sock.listen(5)
    print("Weak test server listening on port 8443 (3DES cipher)...")
    while True:
        conn, addr = sock.accept()
        try:
            with context.wrap_socket(conn, server_side=True) as tls_conn:
                tls_conn.recv(1024)
                tls_conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nweak server ok")
        except Exception as e:
            print(f"Connection error: {e}")