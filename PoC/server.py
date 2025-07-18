from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

# Once we know what is the shellcode it will be added
# Add the path to the shellcode
# with open("...", "rb") as f:
#    PAYLOAD = f.read()

# Placeholder payload for testing
PAYLOAD = "a"*256


# Custom HTTP request handler
class MyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        print(f"[+] POST received on {self.path}")
        print("[+] Headers:")
        for k, v in self.headers.items():
            print(f"    {k}: {v}")

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        print(f"[+] Received {len(post_data)} bytes")

        # Save the received data to a file
        with open("received_data", "wb") as f:
            f.write(post_data)

        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)


httpd = HTTPServer(('0.0.0.0', 443), MyHandler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

# The certificate and key files should be in the Ressources directory (or you can change the code)
context.load_cert_chain(certfile="../Ressources/cert.pem",
                        keyfile="../Ressources/key.pem")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("[*] HTTPS server listening on port 443...")
httpd.serve_forever()
