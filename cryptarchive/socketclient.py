"""cryptarchive socket client."""
import socket
import struct
import hashlib
import StringIO

from Crypto.Cipher import AES
from Crypto.Util import Counter

from zope.interface import implementer

from cryptarchive import constants
from cryptarchive.challenge import Challenge
from cryptarchive.errors import AuthenticationError, VersionError, FileNotFound, ProtocolError
from cryptarchive.index import Index
from cryptarchive.icryptarchive import ICryptarchiveClient


class CryptarchiveSocketConnection(object):
    """
    The CryptarchiveClient using sockets.
    :param addr: target address of server (host, port)
    :type addr: tuple of (str, int)
    :param username: username for login
    :type username: str
    :param password: password for login
    :type password: str
    """
    def __init__(self, addr, username, password):
        self.addr = addr
        self.username = username
        self._password = password
        self._s = None

    def connect(self):
        """connect to the server."""
        if self._s is not None:
            raise Exception("Already connected.")
        self._s = socket.create_connection(self.addr, timeout=10)
        self._handle_version()
        self._handle_auth()

    def close(self):
        """
        Closes the underlying socket connection.
        """
        if self._s is None:
            # just return
            return
        try:
            self._s.close()
        except:
            pass
        self._s = None


    def _send(self, s):
        """
        Sends string s to the server.
        :param s: data to send
        :type s: str
        """
        length = len(s)
        prefix = struct.pack(constants.MESSAGE_LENGTH_PREFIX, length)
        tosend = prefix + s
        self._s.send(tosend)

    def _recv(self):
        """
        Wait for a message from the server and return it.
        :return: the received message
        :rtype: str
        """
        got_prefix = False
        receiving = True
        to_recv = constants.MESSAGE_LENGTH_PREFIX_LENGTH
        data = ""
        while receiving:
            received = self._s.recv(to_recv)
            if received == "":
                self.close()
                return data
            to_recv -= len(received)
            data += received
            if to_recv <= 0:
                if got_prefix:
                    receiving = False
                else:
                    to_recv = struct.unpack(constants.MESSAGE_LENGTH_PREFIX, data)[0]
                    data = ""
                    got_prefix = True
        return data

    def _handle_version(self):
        """
        Sends the version string to the server and wait for the answer.
        """
        self._send(constants.COM_VERSION)
        response = self._recv()
        if response == "VERSION-OK":
            return True
        elif response == "VERSION-FAIL":
            self.close()
            raise VersionError("Version mismatch!")
        else:
            self.close()
            raise ProtocolError("Received invalid version response: '{r}'!".format(r=response))

    def _handle_auth(self):
        """
        Handles the authentication to the server
        """
        self._send(self.username)
        challenge_s = self._recv()

        # solve challenge
        challenge = Challenge.loads(challenge_s)
        solution = challenge.solve(self._password)
        self._send(solution)

        # handle answer
        auth_response = self._recv()
        if auth_response == "AUTH-OK":
            return True
        elif auth_response == "AUTH-FAIL":
            self.close()
            raise AuthenticationError("Authentication failed!")
        else:
            self.close()
            raise ProtocolError("Received invalid auth response: '{a}'!".format(a=auth_response))

    def _get_cipher(self):
        """
        Return a new AES cipher.
        :return: a new AES cipher.
        :rtype: AES
        """
        cipher = AES.new(self._password, AES.MODE_CTR, counter=Counter.new(128))
        return cipher

    def get_file(self, path, write_cb):
        """
        Receive the file specified by path.
        :param path: the virtual path to receive
        :type path: str
        :param write_cb: callable which will be called with any received data
        :type write_cb: callable.
        """
        if self._s is None:
            raise RuntimeError("Not connected!")
        self._send(constants.ACTION_GET + path)
        response = self._recv()
        if response == "O":
            # everyting ok
            cipher = self._get_cipher()
            receiving = True
            while receiving:
                data = self._recv()
                if data == "":
                    receiving = False
                    self.close()
                else:
                    dec = cipher.decrypt(data)
                    write_cb(dec)

        elif response == "E":
            # file not found
            self.close()
            raise FileNotFound("No such file: '{p}'!".format(p=path))
        else:
            # protocol violation
            self.close()
            raise ProtocolError("Received invalid GET answer: '{a}'!".format(a=response))

    def delete_file(self, path):
        """
        Delete the specified file.
        :param path: the path of the file  to delete
        :type path: str
        """
        if self._s is None:
            raise RuntimeError("Not connected!")
        self._send(constants.ACTION_DELETE + path)
        self.close()

    def set_file(self, path, fin):
        """
        Write to path.
        :param path: the virtual path to write to
        :type path: str
        :param fin: file-like object which will be read
        :type fin: file.
        """
        if self._s is None:
            raise RuntimeError("Not connected!")
        self._send(constants.ACTION_SET + path)
        cipher = self._get_cipher()
        sending = True
        while sending:
            data = fin.read(constants.DEFAULT_CLIENT_READ_SIZE)
            if data == "":
                sending = False
            else:
                enc = cipher.encrypt(data)
                self._send(enc)
        self.close()


@implementer(ICryptarchiveClient)
class CryptarchiveSocketClient(object):
    """The client for the cryptoarchive."""
    def __init__(self, host, username, password, port=constants.DEFAULT_PORT, hash_password=True):
        self._username = username
        if hash_password:
            self._password = hashlib.sha256(password).digest()
        else:
            self._password = password
        self._host = host
        self._port = port
        self._index = None

    def new_connection(self):
        """return a new connection."""
        addr = (self._host, self._port)
        client = CryptarchiveSocketConnection(addr, self._username, self._password)
        client.connect()
        return client

    def retrieve_index(self):
        """retrieves the index."""
        conn = self.new_connection()
        f = StringIO.StringIO()
        try:
            conn.get_file(constants.INDEX_FILE_NAME, f.write)
        except FileNotFound:
            self._index = Index.new()
            self.save_index()
        else:
            ic = f.getvalue()
            self._index = Index.loads(ic)

    def save_index(self):
        """save the index to the server."""
        conn = self.new_connection()
        dumped = self._index.dumps()
        sio = StringIO.StringIO(dumped)
        conn.set_file(constants.INDEX_FILE_NAME, sio)

    def listdir(self, path):
        """lists the path content."""
        if self._index is None:
            raise RuntimeError("Index not yet retrieved!")
        if not self._index.dir_exists(path):
            raise ValueError("No such file or directory!")
        content = self._index.listdir(path)
        ret = []
        for name, isdir in content:
            if isdir and not name.endswith("/"):
                name += "/"
            ret.append(name)
        return ret

    def mkdir(self, path):
        """creates a new directory at path."""
        if self._index is None:
            raise RuntimeError("Index not yet retrieved!")
        if self._index.dir_exists(path):
            raise ValueError("Directory already exists!")
        self._index.mkdir(path)
        self.save_index()

    def upload(self, f, dest):
        """upload a file."""
        if self._index is None:
            raise RuntimeError("Index not yet retrieved!")
        fid = self._index.create_file(dest)
        conn = self.new_connection()
        conn.set_file(fid, f)
        self.save_index()

    def download(self, path, f):
        """download a file."""
        if self._index is None:
            raise RuntimeError("Index not yet retrieved!")
        fid = self._index.get_file_id(path)
        conn = self.new_connection()
        conn.get_file(fid, f.write)

    def delete(self, path):
        """delete a file:"""
        if self._index is None:
            raise RuntimeError("Index not yet retrieved!")
        removed = self._index.remove_from_index(path)
        for fid in removed:
            conn = self.new_connection()
            conn.delete_file(fid)
        self.save_index()
