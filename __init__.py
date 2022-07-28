#!/usr/bin/env python3

import threading
import requests
import json
import time

from binaryninja import (
    log_info,
    show_message_box,
    TextLineField,
    IntegerField,
    get_form_input
)

from binaryninja import (
    collaboration,
    is_connected,
    is_authenticated,
    username
)

class MentionNotifierThread(threading.Thread):

    def __init__(self, host, port, name, bv=None, ssl=False):
        
        threading.Thread.__init__(self)

        self.host = host
        self.port = port
        self.name = name
        self.bv = bv
        
        if ssl:
            scheme = 'https://'
        else:
            scheme = 'http://'

        self.baseurl = scheme + host + ':' + str(port)

        self.username = ''
        self.session = None

    def __del__(self):
        if self.session:
            self.session.close()

    def run(self):

        log_info("mention notifier process start.")

        while self._update():

            noti = self._get_notify()
            if not noti:
                time.sleep(1)
                continue

            noti = list(json.loads(noti).values())[0]
            if self.bv:
                file = collaboration.File.get_for_bv(self.bv)
                show_message_box(f"Mention Notifier [{self.name}]", f"{noti['who']} mentioned you at {file.project.name}/{file.name}")
                continue

            show_message_box("Mention Notifier", "Someone mentioned you! - but no bv provided")

        log_info("mention notifier process dead.")

    def _update(self):

        if not is_connected():
            log_info("mention notifier - not connected.")
            return False

        if not is_authenticated():
            log_info("mention notifier - not authenticated.")
            return False

        try:
            response = requests.get(self.baseurl + '/test')
            if response.status_code != 200:
                log_info("mention notifier - server didn't respond 200.")
        except Exception as e:
            log_info("mention notifier - server not respond.")
            return False
        
        self.username = username()
        self.session = requests.Session()
        return True

    def _get_notify(self, timeout=60):
        try:
            response = self.session.get(self.baseurl + '/subscribe?username=' + self.username, timeout=timeout)
            if response.status_code != 200:
                return None
            else:
                return response.text
        except requests.exceptions.ReadTimeout:
            return None

def start_notifier(bv, *args, **kwargs):

    host = TextLineField("host")
    port = IntegerField("port")
    name = TextLineField("name")
    if get_form_input(["Server address", None, host, port, name], "Mention Notifier Setup") != True:
        return

    notifier = MentionNotifierThread(host.result, port.result, name.result, bv=bv)
    notifier.start()

if __name__ != '__main__':
    from binaryninja import PluginCommand
    PluginCommand.register("start mention notifier", "", start_notifier)