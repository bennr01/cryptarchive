"""runner functions for entry points."""
import os
import sys
import argparse
import cmd
import getpass
import pprint

from twisted.internet import reactor, task
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.defer import inlineCallbacks
from twisted.python import log

from cryptarchive import constants
from cryptarchive.challenge import Challenge
from cryptarchive.client import CryptarchiveClient
from cryptarchive.server import CryptarchiveServerFactory


class CreateUserPrompt(cmd.Cmd):
    """REPL-loop for creating users."""

    def __init__(self, factory, ns):
        cmd.Cmd.__init__(self)
        self.factory = factory
        self.ns = ns
        self.prompt = "[{p}]".format(p=os.path.abspath(ns.path))
        self.intro = "Cryptarchive [Python version: {pyv}; protocol version {comv}]\nType 'help' for help.".format(
            pyv=sys.version,
            comv=constants.COM_VERSION,
            )

    def do_quit(self, cmd):
        """quit the REPL-loop"""
        return True

    do_exit = do_q = do_quit

    def do_stop(self, cmd):
        """stop the server."""
        reactor.stop()
        return True

    def do_list_userids(self, cmd):
        """lists  the userids."""
        users = os.listdir(self.ns.path)
        for user in users:
            self.stdout.write(user + "\n")

    def do_get_userid(self, cmd):
        """calculate the userid for the username."""
        uid = self.factory.get_userid(cmd)
        self.stdout.write(uid + "\n")

    def do_remove_user_by_name(self, cmd):
        """remove the user with the username"""
        userid = self.factory.get_userid(cmd)
        p = self.factory.get_user_path(userid)
        if p.exists():
            p.remove()
        else:
            self.stdout.write("Error: No such user!\n")

    def do_remove_user_by_userid(self, cmd):
        """remove the user with the userid"""
        p = self.factory.get_user_path(cmd)
        if p.exists():
            p.remove()
        else:
            self.stdout.write("Error: No such user!\n")

    def do_create_user(self, cmd):
        """create a new user."""
        userid = self.factory.get_userid(cmd)
        if self.factory.user_exists(userid):
            self.stdout.write("Error: user already exists!\n")
            return
        userpath = self.factory.get_user_path(userid)
        password = getpass.getpass("Password for '{un}': ".format(un=cmd))
        authblock, hash = Challenge.generate_authblock_and_hash(password, hash_password=True)
        userpath.makedirs()
        self.factory.get_authblock_path(userid).setContent(authblock)
        self.factory.get_hash_path(userid).setContent(hash)


def server_main():
    """entry point for the server"""
    parser = argparse.ArgumentParser(description="The Cryptarchive Server")
    parser.add_argument("path", action="store", help="path of files")
    parser.add_argument("-i", "--interface", action="store", help="interface to listen on", default="0.0.0.0")
    parser.add_argument("-p", "--port", action="store", type=int, default=constants.DEFAULT_PORT, help="port to listen on")
    parser.add_argument("-v", "--verbose", action="store_true", help="be more verbose")
    parser.add_argument("--manage-users", action="store_true", help="open a REPL-loop for creating users")
    ns = parser.parse_args()

    if not os.path.exists(ns.path):
        print "No such file or directory: '{p}'".format(p=ns.path)
        sys.exit(2)

    if ns.verbose:
        log.startLogging(sys.stdout)

    factory = CryptarchiveServerFactory(ns.path)
    ep = TCP4ServerEndpoint(reactor, port=ns.port, interface=ns.interface)
    ep.listen(factory)

    if ns.manage_users:
        cmdo = CreateUserPrompt(factory, ns)
        cmdo.prompt = cmdo.prompt.format(p=ns.path)
        reactor.callInThread(cmdo.cmdloop)

    reactor.run()


def client_main():
    """entry point for the console client."""
    parser = argparse.ArgumentParser(description="The Cryptarchive commandline client")
    parser.add_argument("-v", "--verbose", action="store_true", help="be more verbose")
    parser.add_argument("host", action="store", help="host to connect to")
    parser.add_argument("-p", "--port", action="store", type=int, default=constants.DEFAULT_PORT, help="port to connect to")
    parser.add_argument("username", action="store", help="username")
    parser.add_argument("password", action="store", help="password")
    parser.add_argument("action", action="store", choices=["ls", "mkdir", "show-index", "upload", "download", "delete"], help="what to do")
    parser.add_argument("orgpath", action="store", help="path to read from / list / create / ...")
    parser.add_argument("dest", action="store", help="path to write to", nargs="?", default=None)
    parser.add_argument("--nohash", action="store_false", dest="hash_password", help="Do not hash password")
    ns = parser.parse_args()

    if ns.verbose:
        log.startLogging(sys.stdout)

    client = CryptarchiveClient(
        host=ns.host,
        port=ns.port,
        username=ns.username,
        password=ns.password,
        hash_password=ns.hash_password,
        )
    task.react(run_client, (client, ns))


@inlineCallbacks
def run_client(reactor, client, ns):
    """runs the client."""
    yield client.retrieve_index()

    if ns.action == "ls":
        content = yield client.listdir(ns.orgpath)
        for fn in content:
            print fn

    elif ns.action == "mkdir":
        yield client.mkdir(ns.orgpath)

    elif ns.action == "show-index":
        pprint.pprint(client._index._index)

    elif ns.action == "upload":
        with open(ns.orgpath, "rb") as fin:
            yield client.upload(fin, ns.dest)

    elif ns.action == "download":
        with open(ns.dest, "wb") as fout:
            yield client.download(ns.orgpath, fout)

    elif ns.action == "delete":
        yield client.delete(ns.orgpath)
