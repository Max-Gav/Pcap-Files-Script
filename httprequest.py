class HTTPRequest:
    def __init__(self, request_string):
        self.method = None
        self.path = None
        self.protocol = None
        self.host = None
        self.connection = None
        self.user_agent = None
        self.accept = None
        self.referer = None
        self.headers = None
        
        # Parse the request string and set attributes accordingly
        self.parse_request(request_string)
        
    def parse_request(self, request_string):
        lines = request_string.split(r'\r\n')
        first_line = lines[0]
        headers = lines[1:]
        self.headers = headers
        
        # Parse the first line (request line)
        method, path, protocol = first_line.split()
        self.method = method
        self.path = path
        self.protocol = protocol
        
        # Parse headers and set attributes
        for header in headers:
            if header.startswith('Host:'):
                self.host = header.split(': ')[1]
            elif header.startswith('Connection:'):
                self.connection = header.split(': ')[1]
            elif header.startswith('User-Agent:'):
                self.user_agent = header.split(': ')[1]
            elif header.startswith('Accept:'):
                self.accept = header.split(': ')[1]
            elif header.startswith('Referer:'):
                self.referer = header.split(': ')[1]
