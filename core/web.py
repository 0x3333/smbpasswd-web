import hashlib
import http.server
import json
from http import HTTPStatus

import os


class RequestHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, Smbpasswd):


    def invalid_api_request(self):
        self.send_error(http.HTTPStatus.BAD_REQUEST, "Invalid API request")

    def set_json_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def get_username(self, provided_token):
        """Return the username associates with the provided token"""

        with open("../res/tokens", "r") as file:
            tokens = [entry.split("\t")
                      for entry in [line.rstrip() for line in file]]

        for token in tokens:
            if token[0] == provided_token:
                return token[1]

    def api_get_username(self, entries):
        """Return the username for a given token"""

        if len(entries) != 1:
            self.invalid_api_request()
            return

        username = self.get_username(entries[0])

        if username is not None:
            self.set_json_headers()
            self.wfile.write(json.dumps(username).encode())
            return

        self.invalid_api_request()

    def api_set_password(self, entries):
        """Define the user's smb password"""

        if len(entries) != 2:
            self.invalid_api_request()
            return

        username = self.get_username(entries[0])

        if username is not None:
            if self.call_smbpasswd(username, entries[1]) == True:
                self.send_response(200)
                self.wfile.write(json.dumps("OK").encode())
                return
            else:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not set password.")
                return

        self.invalid_api_request()

    def generate_hash(self, username):
        return hashlib.sha256(username.encode() + os.urandom(32)).hexdigest()

    def process_api_request(self):
        entries = self.path[1:].split("/")[1:]
        if len(entries) > 0:
            if entries[0] == "get_username":
                self.api_get_username(entries[1:])
            elif entries[0] == "set_password":
                self.api_set_password(entries[1:])
        else:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid API request")

    def do_GET(self):
        """Process API and static files requests"""

        if self.path.startswith("/api/"):
            self.process_api_request()
        else:
            super(SmbpasswdRequestHandler, self).do_GET()

    def list_directory(self):
        """Directory listing disabled"""
        self.send_error(HTTPStatus.FORBIDDEN, "Directory listing forbidden.")
        return None
