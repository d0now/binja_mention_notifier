#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import json
import hmac
import time
import re
from datetime import datetime, timedelta

sessions = {}

class ChatEventHandler(BaseHTTPRequestHandler):
    
    SECRET="VeryVerySecretPassword"

    def __init__(self, *args, **kwargs):

        global sessions

        self.regex = re.compile(r'(@+[a-zA-Z0-9(_)]{1,})')
        self.sessions = sessions
        self.mentions_alive = 10
        self.sessions_alive = 3600

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

    def clean_outdated_sessions(self, basetime=time.time()):
        session_keys = list(self.sessions.keys())
        for start in session_keys:
            if start + self.sessions_alive < basetime:
                print(f"session cleanup: {start} < {basetime}")
                del self.sessions[start]

    def clean_outdated_mentions(self, sessts, basetime=time.time()):

        session = self.sessions[sessts]
        mention_keys = list(session['mentions'].keys())
        for start in mention_keys:
            if start + self.mentions_alive < basetime:
                print(f"mention cleanup: {start} < {basetime}")
                del self.sessions[sessts]['mentions'][start]

    def clean_every_outdated_mentions(self, basetime=time.time()):
        session_keys = list(self.sessions.keys())
        for start in session_keys:
            self.clean_outdated_mentions(start)

    def new_session(self, username, cleanup=True):

        if cleanup:
            self.clean_outdated_sessions()
            self.clean_every_outdated_mentions()

        session = self.get_session_by_username(username, cleanup=False)
        if session:
            return session

        session_start = time.time()
        self.sessions[session_start] = { 'username': username, 'start': session_start, 'mentions': {} }
        return self.sessions[session_start]

    def get_session_by_username(self, username, cleanup=True):
        
        if cleanup:
            self.clean_outdated_sessions()
            self.clean_every_outdated_mentions()

        for session_start in self.sessions:
            session = self.sessions[session_start]
            if session['username'] == username:
                return session

        return None

    def new_mention(self, username, mention, cleanup=True):

        if cleanup:
            self.clean_outdated_sessions()
            self.clean_every_outdated_mentions()

        session = self.get_session_by_username(username, cleanup=False)
        if not session:
            return None

        self.sessions[session['start']]['mentions'][mention['at']] = mention

    def get_mentions_by_username(self, username, cleanup=True):
        
        if cleanup:
            self.clean_outdated_sessions()
            self.clean_every_outdated_mentions()

        session = self.get_session_by_username(username, cleanup=False)
        if not session:
            return None

        mentions = session['mentions']
        if mentions:
            self.sessions[session['start']]['mentions'] = {}

        return mentions

    def validate_webhook(self, body):

        expected = self.headers['X-Binja-Signature']
        if not expected:
            self._set_response_400()
            return False

        digest = hmac.new(b"VeryVerySecretPassword", body, "sha256").hexdigest()

        if not hmac.compare_digest(expected, digest):
            self._set_response_400()
            return False

        return True

    def handle_webhook_event(self):

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

        self._set_response_ok()
        self.wfile.write(b"Ok")

        mentioned = self.regex.search(data['message'])
        if not mentioned:
            return
        else:
            s, e = mentioned.span()
            mentioned_to = data['message'][s+1:e]

        session = self.get_session_by_username(mentioned_to)
        if not session:
            return

        at = datetime.strptime(data['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
        at = at + timedelta(hours=9)

        self.new_mention(mentioned_to, {
            'whom' : mentioned_to,
            'who'  : data['sender'],
            'from' : data['project_file'],
            'at'   : at.timestamp()
        })

    def do_POST(self):
        url = urlparse(self.path)
        if url.path == '/webhook_event':
            self.handle_webhook_event()

    def handle_subscribe(self, query):

        query = parse_qs(query)

        if 'username' not in query:
            self._set_response_400()
            return
        else:
            username = query['username'][0]

        session = self.get_session_by_username(username)
        if not session:
            session = self.new_session(username)

        while session['start'] + self.sessions_alive > time.time() - 10:

            if session['start'] not in self.sessions:
                break

            mentions = self.get_mentions_by_username(username)
            if not mentions:
                time.sleep(1)
                continue

            if self._set_response_ok():
                self.wfile.write(json.dumps(mentions).encode())
            else:
                break

            return

        if session['start'] in self.sessions:
            del self.sessions[session['start']]

        self._set_response_404()
        return

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == '/test':
            self._set_response_ok()
            self.wfile.write(b'Ok\n')
        elif url.path == '/subscribe':
            self.handle_subscribe(url.query)

def run(server_class=ThreadingHTTPServer, handler_class=ChatEventHandler, port=5555):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
