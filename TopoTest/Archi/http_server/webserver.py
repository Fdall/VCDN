import SimpleHTTPServer
import SocketServer

class MyHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

    # Disable logging DNS lookups
    def address_string(self):
        return str(self.client_address[0])


PORT = 80

Handler = MyHandler
Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = SocketServer.TCPServer(("", PORT), Handler)
sa = httpd.socket.getsockname()
print("Server1: httpd serving on "+sa[0]+" port %d" % PORT)
httpd.serve_forever()
