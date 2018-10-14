"""runner functions for entry points."""
import os
import sys
import argparse
import cmd
import getpass
import pprint
import hashlib

from twisted.internet import reactor, task
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.defer import inlineCallbacks
from twisted.python import log

from cryptarchive import constants
from cryptarchive.challenge import Challenge
from cryptarchive.client import CryptarchiveTxClient
from cryptarchive.socketclient import CryptarchiveSocketClient, CryptarchiveSocketConnection
from cryptarchive.server import CryptarchiveServerFactory
from cryptarchive.usermanager import UserManager
from cryptarchive.reconstruct import reconstruct


CLIENTS = {
    "tx": CryptarchiveTxClient,
    "socket": CryptarchiveSocketClient,
}


class CreateUserPrompt(cmd.Cmd):
    """REPL-loop for creating users."""

    def __init__(self, usermanager, ns):
        cmd.Cmd.__init__(self)
        self.usermanager = usermanager
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

    def do_list_userids(self, cmd):
        """lists  the userids."""
        users = os.listdir(self.ns.path)
        for user in users:
            self.stdout.write(user + "\n")

    def do_get_userid(self, cmd):
        """calculate the userid for the username."""
        uid = self.usermanager.get_userid(cmd)
        self.stdout.write(uid + "\n")

    def do_remove_user_by_name(self, cmd):
        """remove the user with the username"""
        userid = self.usermanager.get_userid(cmd)
        p = self.usermanager.get_user_path(userid)
        if p.exists():
            p.remove()
        else:
            self.stdout.write("Error: No such user!\n")

    def do_remove_user_by_userid(self, cmd):
        """remove the user with the userid"""
        p = self.usermanager.get_user_path(cmd)
        if p.exists():
            p.remove()
        else:
            self.stdout.write("Error: No such user!\n")

    def do_create_user(self, cmd):
        """create a new user."""
        userid = self.usermanager.get_userid(cmd)
        if self.usermanager.user_exists(userid):
            self.stdout.write("Error: user already exists!\n")
            return
        userpath = self.usermanager.get_user_path(userid)
        password = getpass.getpass("Password for '{un}': ".format(un=cmd))
        authblock, hash = Challenge.generate_authblock_and_hash(password, hash_password=True)
        userpath.makedirs()
        self.usermanager.get_authblock_path(userid).setContent(authblock)
        self.usermanager.get_hash_path(userid).setContent(hash)

    def do_reconstruct_index(self, cmd):
        """attemp reconstruct the index of the user with the userid."""
        p = self.usermanager.get_user_path(cmd)
        if not p.exists():
            self.stdout.write("Error: No such user!\n")
            return

        # decrypt old index
        enc_old_index = p.child(constants.INDEX_FILE_NAME).getContent()
        password = getpass.getpass("Password for '{un}': ".format(un=cmd))
        hp = hashlib.sha256(password).digest()
        conn = CryptarchiveSocketConnection("", "", hp)
        cipher = conn._get_cipher()
        old_index = cipher.decrypt(enc_old_index)

        filelist = p.listdir()
        for fn in (constants.INDEX_FILE_NAME, "hash.bin", "authblock.bin"):
            if fn in filelist:
                filelist.remove(fn)
        index = reconstruct(old_index, filelist, verbose=True)

        # encrypt new index
        cipher = conn._get_cipher()
        enc_index = cipher.encrypt(index.dumps())
        p.child(constants.INDEX_FILE_NAME).setContent(enc_index)


def scan_dir_for_upload(path, remotebase):
    """
    Scans a directory for uploading a directory.
    :param path: path to scan
    :type path: str
    :param remotebase: path to which should be uploaded.
    :tyype remotebase: str
    :return: A tuple ([directories to create], [(sourcefile, targetfile)])
    :rtype: tuple of (list of str, list of tuples of (str, str))
    """
    dirs_to_create = []
    files_to_upload = []
    for fn in os.listdir(path):
        fp = os.path.join(path, fn)
        rp = os.path.join(remotebase, fn)
        if os.path.isdir(fp):
            dirs_to_create.append(rp)
            sd, sf = scan_dir_for_upload(fp, rp)
            dirs_to_create += sd
            files_to_upload += sf
        elif os.path.isfile(fp):
            files_to_upload.append((fp, rp))
        else:
            raise NotImplementedError("Can not handle: {p}".format(p=fp))
    return (dirs_to_create, files_to_upload)



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

    if ns.manage_users:
        usermanager = UserManager(ns.path)
        cmdo = CreateUserPrompt(usermanager, ns)
        cmdo.prompt = cmdo.prompt.format(p=ns.path)
        cmdo.cmdloop()
        sys.exit(0)

    if ns.verbose:
        log.startLogging(sys.stdout)

    factory = CryptarchiveServerFactory(ns.path, verbose=ns.verbose)
    ep = TCP4ServerEndpoint(reactor, port=ns.port, interface=ns.interface)
    ep.listen(factory)

    reactor.run()


def client_main():
    """entry point for the console client."""
    parser = argparse.ArgumentParser(description="The Cryptarchive commandline client")
    parser.add_argument("-v", "--verbose", action="store_true", help="be more verbose")
    parser.add_argument("host", action="store", help="host to connect to")
    parser.add_argument("-p", "--port", action="store", type=int, default=constants.DEFAULT_PORT, help="port to connect to")
    parser.add_argument("--nohash", action="store_false", dest="hash_password", help="Do not hash password")
    parser.add_argument("username", action="store", help="username")
    parser.add_argument("password", action="store", help="password")
    parser.add_argument("action", action="store", choices=["ls", "mkdir", "show-index", "upload", "download", "delete", "download-raw", "mv"], help="what to do")
    parser.add_argument("orgpath", action="store", help="path to read from / list / create / ...")
    parser.add_argument("dest", action="store", help="path to write to", nargs="?", default=None)
    parser.add_argument("-c", "--client", action="store", choices=["tx", "socket"], default="tx")
    ns = parser.parse_args()

    if ns.verbose:
        log.startLogging(sys.stdout)

    client_class = CLIENTS[ns.client]
    client = client_class(
        host=ns.host,
        port=ns.port,
        username=ns.username,
        password=ns.password,
        hash_password=ns.hash_password,
        )
    if ns.client == "tx":
        task.react(run_tx_client, (client, ns))
    elif ns.client == "socket":
        run_socket_client(client, ns)
    else:
        raise ValueError("Unexpected value for -c/--client")


@inlineCallbacks
def run_tx_client(reactor, client, ns):
    """runs the twisted client."""
    if ns.action != "download-raw":
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

        if os.path.isdir(ns.orgpath):
            dtc, ftu = scan_dir_for_upload(ns.orgpath, ns.dest)
        else:
            dtc = []
            ftu = [(ns.orgpath, ns.dest)]

        for dn in dtc:
            yield client.mkdir(dn)

        for lp, rp in ftu:
            with open(lp, "rb") as fin:
                print("Uploading '{o}' as '{d}'...".format(o=lp, d=rp))
                yield client.upload(fin, rp)

    elif ns.action == "download":
        with open(ns.dest, "wb") as fout:
            yield client.download(ns.orgpath, fout)

    elif ns.action == "download-raw":
        with open(ns.dest, "wb") as fout:
            yield client.download_raw(ns.orgpath, fout)

    elif ns.action == "delete":
        yield client.delete(ns.orgpath)

    elif ns.action == "mv":
        yield client.move(ns.orgpath, ns.dest)


def run_socket_client(client, ns):
    """runs the socket client."""
    if ns.action != "download-raw":
        client.retrieve_index()

    if ns.action == "ls":
        content = client.listdir(ns.orgpath)
        for fn in content:
            print fn

    elif ns.action == "mkdir":
        client.mkdir(ns.orgpath)

    elif ns.action == "show-index":
        pprint.pprint(client._index._index)

    elif ns.action == "upload":
        if os.path.isdir(ns.orgpath):
            dtc, ftu = scan_dir_for_upload(ns.orgpath, ns.dest)
        else:
            dtc = []
            ftu = [(ns.orgpath, ns.dest)]

        for dn in dtc:
            client.mkdir(dn)

        for lp, rp in ftu:
            with open(lp, "rb") as fin:
                print("Uploading '{o}' as '{d}'...".format(o=lp, d=rp))
                client.upload(fin, rp)

    elif ns.action == "download":
        with open(ns.dest, "wb") as fout:
            client.download(ns.orgpath, fout)

    elif ns.action == "download-raw":
        with open(ns.dest, "wb") as fout:
            client.download_raw(ns.orgpath, fout)

    elif ns.action == "delete":
        client.delete(ns.orgpath)

    elif ns.action == "mv":
        client.move(ns.orgpath, ns.dest)
