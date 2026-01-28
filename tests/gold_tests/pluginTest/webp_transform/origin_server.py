import http.server
import socketserver
import sys
import mimetypes
import os

# Add explicit MIME types support to ensure Plugin detects them correctly
mimetypes.add_type('image/avif', '.avif')
mimetypes.add_type('image/webp', '.webp')

if len(sys.argv) < 3:
    print("Usage: python3 origin_server.py <port> <directory>")
    sys.exit(1)

port = int(sys.argv[1])
directory = sys.argv[2]


class Handler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)


# Allow reuse address to prevent "Address already in use" errors during rapid testing
socketserver.TCPServer.allow_reuse_address = True

with socketserver.TCPServer(("", port), Handler) as httpd:
    print(f"Custom Origin Serving at port {port} from {directory}")
    httpd.serve_forever()
