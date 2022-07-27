import binaryninja
import threading
import requests
import json
import time

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

        binaryninja.log_info("mention notifier process start.")

        while self._update():

            noti = self._get_notify()
            if not noti:
                time.sleep(1)
                continue

            noti = list(json.loads(noti).values())[0]
            if self.bv:
                binaryninja.show_message_box(f"Mention Notifier [{self.name}]", f"{noti['who']} mentioned you at {self.bv.file.filename}")
                continue

            binaryninja.show_message_box("Mention Notifier", "Someone mentioned you! - but no bv provided")

        binaryninja.log_info("mention notifier process dead.")

    def _update(self):

        if not binaryninja.is_connected():
            binaryninja.log_info("mention notifier - not connected.")
            return False

        if not binaryninja.is_authenticated():
            binaryninja.log_info("mention notifier - not authenticated.")
            return False

        try:
            response = requests.get(self.baseurl + '/test')
            if response.status_code != 200:
                binaryninja.log_info("mention notifier - server didn't respond 200.")
        except Exception as e:
            binaryninja.log_info("mention notifier - server not respond.")
            return False
        
        self.username = binaryninja.username()
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

    host = binaryninja.TextLineField("host")
    port = binaryninja.IntegerField("port")
    name = binaryninja.TextLineField("name")
    if binaryninja.get_form_input(["Server address", None, host, port, name], "Mention Notifier Setup") != True:
        return

    notifier = MentionNotifierThread(host.result, port.result, name.result, bv=bv)
    notifier.start()

from binaryninja import PluginCommand
PluginCommand.register("start mention notifier", "", start_notifier)