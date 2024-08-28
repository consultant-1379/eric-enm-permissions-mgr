from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import ssl

import OpenSSL
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

hostName = "localhost"
serverPort = 8443
test = ["/eric-enm-credm-controller-d6c4f8cdc-jzffd", "/eric-enm-credm-controller-d6c4f8cdc-jzffd4"]

class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        print(self.connection)

        print(self.connection.getpeername())
        print(self.connection.getpeercert())
        
        x509_cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, self.connection.getpeercert(True)
            
        )
        print(x509_cert)
        print(x509_cert.get_subject())
        # print(x509_cert.subject.rfc4514_string())
        try:
            test.remove(self.path)
            print(test)
        except Exception as e:
            print(e)
        self.wfile.write(bytes("ok", "utf-8"))
        
if __name__ == "__main__":        
    webServer = HTTPServer((hostName, serverPort), CallbackHandler)
    print("Server started http://%s:%s" % (hostName, serverPort))


    webServer.socket = ssl.wrap_socket (webServer.socket, 
        keyfile="serverp.key", 
        certfile='server.crt', 
        server_side=True, 
        cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS,
        ca_certs='ca.crt',
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
        ciphers=''
    )

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")