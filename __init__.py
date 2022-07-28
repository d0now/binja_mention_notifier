#!/usr/bin/env python3

import json
import re
import requests
import threading
import time

from urllib.parse import urlparse

from binaryninja import (
    show_message_box,
    MessageBoxIcon,
    TextLineField,
    ChoiceField,
    get_form_input,
)

from binaryninja import (
    is_connected,
    is_authenticated,
    username
)

from binaryninja.collaboration import (
    Remote,
    Project,
    File
)

from binaryninja import BackgroundTaskThread

import urllib3
urllib3.disable_warnings()

INTERACTION_TITLE = "Mention Notifier"

def binja_api_auth(api_addr, username, password):

    session = requests.Session()
    
    response = session.get(api_addr + "/api-auth/login/", verify=False)
    if response.status_code != 200:
        return None

    needle = "name=\"csrfmiddlewaretoken\" value=\""
    to_parse = response.text
    start = to_parse.find(needle)
    if start == -1:
        return None

    to_parse = to_parse[start + len(needle):]
    end = to_parse.find("\"")
    if end == -1:
        return None

    csrfmiddlewaretoken = to_parse[:end]

    response = session.post(
        api_addr + "/api-auth/login/",
        headers={
            'Referer': api_addr + '/api-auth/login/'
        },
        data={
            'csrfmiddlewaretoken': csrfmiddlewaretoken,
            'next': '/api/',
            'username': username,
            'password': password,
            'submit': 'Log in'
        },
        verify=False
    )

    if response.status_code != 200:
        return None

    return session

class MentionNotifierThread(threading.Thread):

    def __init__(self, bv, password, notify_method='log'):
        
        threading.Thread.__init__(self)

        self.bv = bv
        self.password = password
        self.notify_method = notify_method
        self.logger = bv.create_logger('Mention Notifier')

        self.file = File.get_for_bv(bv)
        self.project = self.file.project
        self.remote = self.project.remote
    
        self.notify_addr = urlparse(self.remote.address).netloc.split(":")[0]
        self.notify_port = 5555
        self.notify_url = 'http://' + self.notify_addr + ':' + str(self.notify_port)

        self.username = ''
        self.session = None
        self.last_check = time.time()
        self.running = False

    def __del__(self):
        if self.session:
            self.session.close()

    def notify_to_user(self, message):
        if self.notify_method == 'messagebox':
            show_message_box(INTERACTION_TITLE, self.project.name + ' - ' + self.file.name + ':\n\n' + message)
        elif self.notify_method == 'log':
            self.logger.log_warn(self.project.name + ' - ' + self.file.name + ' : ' + message)

    def run(self):

        self.logger.log_info("mention notifier process start.")

        self.running = True
        while self.running and self._update():

            notify = self._get_notify()
            if not notify:
                time.sleep(1)
                continue

            mention = self._get_mention()
            if not mention:
                self.notify_to_user("Someone mentioned you but failed to get message.")
            else:
                self.notify_to_user(f"<{mention['sender']}> {mention['message']}")

        self.logger.log_info("mention notifier process dead.")

    def _update(self):

        if not is_connected():
            self.logger.log_error("mention notifier - not connected.")
            return False

        if not is_authenticated():
            self.logger.log_error("mention notifier - not authenticated.")
            return False

        try:
            response = requests.get(self.notify_url + '/test')
            if response.status_code != 200:
                self.logger.log_error("mention notifier - server didn't respond 200.")
                return False

        except Exception as e:
            self.logger.log_error("mention notifier - server not respond.")
            return False
        
        self.username = username()
        self.session = requests.Session()
        return True

    def _get_notify(self, timeout=60):

        try:
            response = self.session.get(self.notify_url + '/subscribe?username=' + self.username, timeout=timeout)
        except requests.exceptions.ReadTimeout:
            return None

        if response.status_code != 200:
            return None

        return response.text

    def _get_mention(self):

        session = binja_api_auth(self.remote.address, self.username, self.password)
        if not session:
            self.logger.log_error("Failed to authenticated to binaryninja api server.")
            return None

        response = session.get(self.file.chat_log_url, headers={'Accept': 'application/json'})
        if response.status_code != 200:
            self.logger.log_error("Failed to get chat log from binaryninja api server.")
            return None

        chat_logs = json.loads(response.text)

        for chat_log in chat_logs:

            if chat_log['timestamp'] < self.last_check:
                continue

            found = re.search(r'(@+[a-zA-Z0-9(_)]{1,})', chat_log['message'])
            if not found:
                continue

            start, end = found.span()
            mentioned = chat_log['message'][start+1:end]
            if mentioned != self.username:
                continue

            self.last_check = time.time()
            return chat_log

        return None

def start_notifier(bv, *args, **kwargs):

    global notifiers
    if bv in notifiers:
        show_message_box(INTERACTION_TITLE, "There are already notifier thread running.", icon=MessageBoxIcon.ErrorIcon)
        return

    password = TextLineField("password")
    notify_type = ChoiceField("notify method", ["messagebox", "log"], 1)
    if get_form_input(["Setup", None, password, notify_type], INTERACTION_TITLE) != True:
        show_message_box(INTERACTION_TITLE, "No input?", icon=MessageBoxIcon.ErrorIcon)
        return

    if not password.result:
        show_message_box(INTERACTION_TITLE, "Please enter password.", icon=MessageBoxIcon.ErrorIcon)
        return
    else:
        password = password.result

    if notify_type.result == 0:
        notify_type = "messagebox"
    else:
        notify_type = "log"

    notifier = MentionNotifierThread(bv, password, notify_type)
    notifier.start()
    notifiers[bv] = notifier

class NotifierKiller(BackgroundTaskThread):

    def __init__(self, target_thread):
        self.target_thread = target_thread
        BackgroundTaskThread.__init__(self)

    def run(self):
        self.target_thread.running = False
        self.target_thread.join()

def stop_notifier(bv, *args, **kwargs):

    global notifiers
    if bv not in notifiers:
        show_message_box(INTERACTION_TITLE, "There are no notifier thread running.", icon=MessageBoxIcon.ErrorIcon)
        return

    NotifierKiller(notifiers[bv]).start()
    del notifiers[bv]

if __name__ != '__main__':

    if 'notifiers' not in dir():
        notifiers = {}

    from binaryninja import PluginCommand
    PluginCommand.register("Start mention notifier", "", start_notifier)
    PluginCommand.register("Stop mention notifier", "", stop_notifier)