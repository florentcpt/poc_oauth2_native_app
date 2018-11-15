from http.server import BaseHTTPRequestHandler, HTTPServer, HTTPStatus

_path = ''


class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global _path
        _path = self.path
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Lenght', len(self.path))
        self.end_headers()
        self.wfile.write(bytes(self.path, 'utf8'))


def run(server_class=HTTPServer, handler_class=MyHTTPRequestHandler):
    server_address = ('', 8000)
    httpd = server_class(server_address, handler_class)
    #httpd.serve_forever()
    httpd.handle_request()


def main():
    run()
    print(_path)

if __name__ == '__main__':
    main()