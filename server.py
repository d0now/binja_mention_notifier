#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import json
import hmac
import time
import re

sessions = {}

class ChatEventHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, secret='', session_timeout=300, **kwargs):
        self.regex = re.compile(r'(@+[a-zA-Z0-9(_)]{1,})')
        self.secret = secret
        self.session_timeout = session_timeout
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def _set_response_ok(self):
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            return True
        except BrokenPipeError:
            return False

    def _set_response_400(self):
        try:
            self.send_response(400)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            return True
        except BrokenPipeError:
            return False

    def _set_response_404(self):
        try:
            self.send_response(404)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            return True
        except BrokenPipeError:
            return False

    def _set_response_408(self):
        try:
            self.send_response(408)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            return True
        except BrokenPipeError:
            return False

    def _set_response_423(self):
        try:
            self.send_response(423)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            return True
        except BrokenPipeError:
            return False

    def _set_response_500(self):
        try:
            self.send_response(500)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            return True
        except BrokenPipeError:
            return False

    def validate_webhook(self, body):

        if not self.secret:
            return True

        expected = self.headers['X-Binja-Signature']
        if not expected:
            self._set_response_400()
            return False

        digest = hmac.new(self.secret.encode(), body, "sha256").hexdigest()

        if not hmac.compare_digest(expected, digest):
            self._set_response_400()
            return False

        return True

    def handle_webhook_event(self):

        global sessions

        if not self.headers['Content-Length']:
            return

        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)

        if not self.validate_webhook(body):
            return

        event = json.loads(body)
        if 'data' not in event:
            self._set_response_400()
            return
        else:
            data = event['data']

        if not {'project_file', 'sender', 'message', 'timestamp'} <= set(data):
            self._set_response_400()
            return

        if self._set_response_ok():
            self.wfile.write(b"Ok")

        mentioned = self.regex.search(data['message'])
        if mentioned:
            s, e = mentioned.span()
            mentioned_to = data['message'][s+1:e]
            if mentioned_to in sessions and sessions[mentioned_to] == None:
                sessions[mentioned_to] = data['project_file']

    def do_POST(self):
        url = urlparse(self.path)
        if url.path == '/webhook_event':
            self.handle_webhook_event()

    def handle_subscribe(self, query):

        global sessions

        query = parse_qs(query)

        if 'username' not in query:
            self._set_response_400()
            return
        else:
            username = query['username'][0]

        if 'project_file' not in query:
            self._set_response_400()
            return
        else:
            project_file = query['project_file'][0]

        if username in sessions:
            sessions[username] = -1
            self._set_response_423()
            return

        sessions[username] = None
        session_start = time.time()

        while session_start + self.session_timeout > time.time():

            if sessions[username] == None:
                time.sleep(1)
                continue
            elif type(sessions[username]) == str and sessions[username] == project_file:
                if self._set_response_ok():
                    self.wfile.write(str(sessions[username]).encode())
            elif type(sessions[username]) == int and sessions[username] < 0:
                self._set_response_423()
            else:
                self._set_response_500()

            del sessions[username]
            return

        del sessions[username]
        self._set_response_408()
        return

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == '/test':
            if self._set_response_ok():
                self.wfile.write(b'Ok\n')
        elif url.path == '/subscribe':
            self.handle_subscribe(url.query)

def ChatEventHandlerFactory(secret=''):
    def wrapper(*args, **kwargs):
        return ChatEventHandler(*args, secret=secret, **kwargs)
    return wrapper

if __name__ == '__main__':
    
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", default="0.0.0.0")
    parser.add_argument("-p", "--port", default=5555, type=int)
    parser.add_argument("-s", "--secret", default='')
    args = parser.parse_args()

    handler = ChatEventHandlerFactory(args.secret)

    httpd = ThreadingHTTPServer((args.addr, args.port), handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()