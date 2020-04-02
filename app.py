#!/usr/bin/env python3
"""smbpasswd-web is a simple web interface to smbpasswd.

The only purpose is to allow a user to change its samba password using a webbrowser,
no user adding, no machine account, nothing, plain simple changing a password.
"""

import argparse
import hashlib
import http.server
import json
import os
import socket
import ssl
import subprocess
import sys
import traceback
from http import HTTPStatus
from pathlib import Path

__author__ = "Tercio Gaudencio FIlho"
__copyright__ = "Copyright 2019, Tercio Gaudencio Filho"
__credits__ = ["Tercio Gaudencio Filho"]
__license__ = "MIT"
__version__ = "1.0.0"
__maintainer__ = "Tercio Gaudencio FIlho"
__email__ = "terciofilho [at] gmail.com"
__status__ = "Production"

_DEFAULT_HTTP_PORT = 8080
_DEFAULT_HTTPS_PORT = 8443

_DEFAULT_ADDRESS = "localhost"

_DEFAULT_SSL_CERT = "res/fullchain.pem"
_DEFAULT_SSL_KEY = "res/privkey.pem"

_use_sudo = False
_verbose = False

def _start_web_server(ssl_cert, ssl_key, address, port):
    # Change working dir to app root folder
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    httpd = http.server.HTTPServer((address, port), SmbpasswdRequestHandler)
    if ssl_cert and ssl_key and os.path.isfile(ssl_cert) and os.path.isfile(ssl_key):
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile=ssl_cert, keyfile=ssl_key, server_side=True)
    # Change working dir to static resources folder
    os.chdir("static")
    httpd.serve_forever()

def _generate_token(username):
    # TODO: Validate the username provided

    token = None
    with open("res/tokens", "r") as file:
        for line in [line.rstrip() for line in file]:
            tokens = line.split("\t")
            if tokens[0] == username:
                token = tokens[1]
                break;

    if token is None:
        token = hashlib.sha256(username.encode() + os.urandom(32)).hexdigest()

        with open("res/tokens", "a") as file:
            file.write(f"{username}\t{token}\n")

    # TODO: Must have a configuration file, so the generated URL is correct
    print("Token generated:\n")
    print(f"http://{socket.gethostname()}/?{token}")


class SmbpasswdRequestHandler(http.server.SimpleHTTPRequestHandler):

    def invalid_api_request(self):
        self.send_error(HTTPStatus.BAD_REQUEST, "Invalid API request")

    def set_json_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def log_message(self, format, *args):
        if _verbose:
            http.server.SimpleHTTPRequestHandler.log_message(self, format, *args)

    def _call_smbpasswd(self, username, password):
        args = ["sudo", "samba-tool", "user", "setpassword","--newpassword="+password, username]
        if not _use_sudo:
            args = args[1:]
        try:
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            _, std_err = proc.communicate()
            if proc.returncode == 0:
                return True
            else:
                print("smbpasswd returned", proc.returncode)
                print("stderr:", std_err.decode("UTF-8"))
                return False
        except:
            print("Failed to change user password!")
            traceback.print_exc(file=sys.stdout)
            return False

    def get_username(self, provided_token):
        """Return the username associates with the provided token"""

        with open("../res/tokens", "r") as file:
            tokens = [entry.split("\t") for entry in [line.rstrip() for line in file]]

        for token in tokens:
            if token[1] == provided_token:
                return token[0]

    def remove_token(self, provided_token):
        """Remove a token that has been used"""

        lines = []
        with open("../res/tokens", "r") as file:
            lines = file.readlines()

        with open("../res/tokens", "w") as file:
            for line in [line.rstrip() for line in lines]:
                token = line.split("\t")
                if token[1] != provided_token:
                    file.write(f"{line}\n")

    def api_get_username(self, json_body):
        """Return the username for a given token"""

        if "token" not in json_body:
            self.invalid_api_request()
            return

        username = self.get_username(json_body["token"])
        if username is None:
            self.invalid_api_request()
            return

        self.set_json_headers()
        self.wfile.write(json.dumps({"username":username}).encode())

    def api_set_password(self, json_body):
        """Define the user's smb password"""

        if "token" not in json_body and "password" not in json_body:
            self.invalid_api_request()
            return

        token = json_body["token"]
        password = json_body["password"]
        username = self.get_username(token)

        if username is None:
            self.invalid_api_request()
            return

        if self._call_smbpasswd(username, password) == True:
            self.remove_token(token)
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status":"OK"}).encode())
        else:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not set password.")

    def do_GET(self):
        """Process Static files requests"""

        super(SmbpasswdRequestHandler, self).do_GET()

    def do_POST(self):
        """Process API"""

        if self.path.startswith("/api/"):
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            json_body = json.loads(body.decode('utf-8'))

            entries = self.path[1:].split("/")[1:]
            if len(entries) > 0:
                if entries[0] == "get_username":
                    self.api_get_username(json_body)
                elif entries[0] == "set_password":
                    self.api_set_password(json_body)
            else:
                self.send_error(HTTPStatus.BAD_REQUEST, "Invalid API request")
        else:
            super(SmbpasswdRequestHandler, self).do_POST()

    def list_directory(self):
        """Disable directory listing"""
        self.send_error(HTTPStatus.FORBIDDEN, "Directory listing forbidden.")
        return None


def main():
    global _use_sudo
    global _verbose

    parser = argparse.ArgumentParser(
        description="smbpasswd web interface", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    subparsers = parser.add_subparsers(dest="command", help="Commands available")

    # Server command
    parser_server = subparsers.add_parser("server", help="Start then webserver")
    parser_server.add_argument("-a", "--address",help="Address to bind (default: %(default)s)", default=_DEFAULT_ADDRESS)
    parser_server.add_argument("-p", "--port", help=f"Port number to bind.  (default: If SSL, {_DEFAULT_HTTPS_PORT}, otherwise {_DEFAULT_HTTP_PORT})")

    parser_server.add_argument("-v", "--verbose", help="Log HTTP requests", action="store_true")

    parser_server.add_argument("--sudo", help="Use sudo to call smbpasswd", action="store_true")

    parser_server.add_argument("--ssl", help="Start webserver using SSL", action="store_true")
    parser_server.add_argument("--ssl-cert",help="SSL certificate to use (default: %(default)s)", default=_DEFAULT_SSL_CERT)
    parser_server.add_argument("--ssl-key",help="SSL certificate private key (default: %(default)s)", default=_DEFAULT_SSL_KEY)

    # Token command
    parser_token = subparsers.add_parser("gen-token", help="enerate a token to a username")
    parser_token.add_argument("username", metavar="USERNAME", help="Username")

    # Parse arguments
    _args = parser.parse_args()
    if not os.path.exists("res"):
        os.mkdir("res")

    if not os.path.exists("res/tokens"):
        Path("res/tokens").touch()

    if _args.command == "server":
        # If we should print HTTP requests
        _verbose = _args.verbose

        if _args.port is None:
            _args.port = _DEFAULT_HTTPS_PORT if _args.ssl else _DEFAULT_HTTP_PORT

        _use_sudo = _args.sudo
        _start_web_server(_args.ssl_cert, _args.ssl_key, _args.address, int(_args.port))
    elif _args.command == "gen-token":
        _generate_token(_args.username)
    else:
        print("Invalid arguments.")


if __name__ == "__main__":
    main()
