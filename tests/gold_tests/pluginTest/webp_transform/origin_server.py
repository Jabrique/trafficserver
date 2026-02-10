import http.server
import socketserver
import sys
import mimetypes
import os
from urllib.parse import urlparse, parse_qs

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
    
    def end_headers(self):
        """Override to customize headers based on query params"""
        # Parse query string from request path
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)
        
        # Query param: ?no_content_type=1 → Skip Content-Type header
        if query_params.get('no_content_type', ['0'])[0] == '1':
            # Content-Type already sent by send_header(), we can't remove it
            # Instead, we'll handle this in send_header override
            pass
        
        # Query param: ?content_type_extra=charset → Add semicolon parameters
        content_type_extra = query_params.get('content_type_extra', [''])[0]
        if content_type_extra == 'charset':
            # Modify Content-Type to include charset
            # This needs to be done in send_header override
            pass
        
        super().end_headers()
    
    def send_header(self, keyword, value):
        """Override to customize specific headers"""
        # Parse query string
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)
        
        # Skip Content-Type header if requested
        if keyword.lower() == 'content-type':
            if query_params.get('no_content_type', ['0'])[0] == '1':
                # Don't send Content-Type header
                return
            
            # Add extra parameters to Content-Type if requested
            content_type_extra = query_params.get('content_type_extra', [''])[0]
            if content_type_extra == 'charset':
                value = f"{value}; charset=utf-8"
            elif content_type_extra == 'multi':
                value = f"{value}; charset=utf-8; boundary=----WebKitFormBoundary"
        
        super().send_header(keyword, value)


# Allow reuse address to prevent "Address already in use" errors during rapid testing
socketserver.TCPServer.allow_reuse_address = True

with socketserver.TCPServer(("", port), Handler) as httpd:
    print(f"Custom Origin Serving at port {port} from {directory}")
    httpd.serve_forever()
