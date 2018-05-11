"""cryptarchive twisted client."""
import hashlib
import StringIO

from Crypto.Cipher import AES
from Crypto.Util import Counter

from zope.interface import implementer

from twisted.internet import reactor, endpoints, threads
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.protocols.basic import IntNStringReceiver

from cryptarchive import constants
from cryptarchive.challenge import Challenge
from cryptarchive.errors import AuthenticationError, VersionError, FileNotFound
from cryptarchive.index import Index
from cryptarchive.icryptarchive import ICryptarchiveClient


class CryptarchiveClientProtocol(IntNStringReceiver):
    """
    The Protocol for the cryptarchive client.
    For security reasons, each protocol instance is one-user only.
    :param username: the username to use.
    :type username: str
    :param password: password to use
    :type password: str
    :param d: deferred which will be fired when the authentication is finished or it failed
    :type d: Deferred
    """
    structFormat = constants.MESSAGE_LENGTH_PREFIX
    prefixLength = constants.MESSAGE_LENGTH_PREFIX_LENGTH
    MAX_LENGTH = constants.MAX_MESSAGE_LENGTH

    # state constants
    STATE_WAIT_VERSION_RESPONSE = 8
    STATE_WAIT_CHALLENGE = 1
    STATE_WAIT_VALIDATION = 2
    STATE_READY = 3
    STATE_ERROR = 4
    STATE_WAIT_GET_RESPONSE = 9
    STATE_RECEIVING = 5
    STATE_SENDING = 6
    STATE_FINISHED = 7

    def __init__(self, username, password, d=None):
        self._username = username
        self._password = password
        self._d = d
        self._end_d = None
        self._write_cb = None
        self._used = False
        self._state = self.STATE_WAIT_VERSION_RESPONSE
        self._readf = None
        self._cipher = None

    def connectionMade(self):
        """called when the connection was established."""
        self._send_version()

    def stringReceived(self, s):
        """called when a string was received."""
        if self._state == self.STATE_WAIT_VERSION_RESPONSE:
            if s == "VERSION-OK":
                self._state = self.STATE_WAIT_CHALLENGE
                self._send_username()
            elif s == "VERSION-FAIL":
                self._state = self.STATE_ERROR
                self.on_version_mismatch()
                self.transport.loseConnection()
            else:
                self._state = self.STATE_ERROR
                self.on_error("Invalid version answer!")
                self.transport.loseConnection()


        elif self._state == self.STATE_WAIT_CHALLENGE:
            self._solve_challenge(s)
            self._state = self.STATE_WAIT_VALIDATION

        elif self._state == self.STATE_WAIT_VALIDATION:
            if s == "AUTH-OK":
                self._ready = True
                self._state = self.STATE_READY
                if self._d is not None:
                    self._d.callback(self)
            elif s == "AUTH-FAIL":
                self._state = self.STATE_ERROR
                self.on_auth_fail()
                self.transport.loseConnection()
            else:
                self._state = self.STATE_ERROR
                self.on_error("Invalid auth answer!")
                self.transport.loseConnection()

        elif self._state == self.STATE_READY:
            pass

        elif self._state == self.STATE_WAIT_GET_RESPONSE:
            if s == "E":
                self._state = self.STATE_ERROR
                self.transport.loseConnection()
                self._end_d.errback(FileNotFound("No such file!"))
            elif s == "O":
                self._state = self.STATE_RECEIVING
            else:
                self._state = self.STATE_ERROR
                self.on_error("Invalid GET answer!")
                self.transport.loseConnection()

        elif self._state == self.STATE_RECEIVING:
            if self._write_cb is not None:
                if self._cipher is not None:
                    dec = self._cipher.decrypt(s)
                    self._write_cb(dec)
                else:
                    self._write_cb(s)

        elif self._state == self.STATE_FINISHED:
            pass

        else:
            # logic error
            self.on_error("LogicError: reached invalid state.")
            self._state = self.STATE_ERROR
            self.transport.loseConnection()

    def connectionLost(self, reason):
        """called when the connection was lost."""
        self._username = None
        self._password = None
        self._cipher = None
        if self._state != self.STATE_ERROR:
            self._state = self.STATE_FINISHED
            if self._end_d is not None:
                self._end_d.callback(self)

    def _send_version(self):
        """send the communication protocol version to the server."""
        self.sendString(constants.COM_VERSION)

    def _send_username(self):
        """send the username to the server."""
        self.sendString(self._username)

    def _solve_challenge(self, s):
        """
        Solve the challenge.
        :param s: serialized challenge
        :type s: str
        :return: the solution of the challenge
        :rtype: str
        """
        challenge = Challenge.loads(s)
        solution = challenge.solve(self._password)
        self.sendString(solution)

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
        :return: a deferred which will be called once the file has been received.
        :rtype: Deferred
        """
        if self._state != self.STATE_READY:
            raise RuntimeError("Protocol not (yet) ready!")
        if self._used:
            raise RuntimeError("Protocols are one-time-use only!")
        self._used = True
        self._end_d = Deferred()
        self._write_cb = write_cb
        self._cipher = self._get_cipher()
        self._state = self.STATE_WAIT_GET_RESPONSE
        self.sendString(constants.ACTION_GET + path)
        return self._end_d

    def delete_file(self, path):
        """
        Delete the specified file.
        :param path: the path of the file  to delete
        :type path: str
        :return: a deferred which will be called when the file was deleted.
        :rtype: Deferred
        """
        if self._state != self.STATE_READY:
            raise RuntimeError("Protocol not (yet) ready!")
        if self._used:
            raise RuntimeError("Protocols are one-time-use only!")
        self._used = True
        self._end_d = Deferred()
        self.sendString(constants.ACTION_DELETE + path)
        return self._end_d

    @inlineCallbacks
    def set_file(self, path, fin):
        """
        Write to path.
        :param path: the virtual path to write to
        :type path: str
        :param fin: file-like object which will be read
        :type fin: file.
        :return: a deferred which will be called once the file has been written.
        :rtype: Deferred
        """
        if self._state != self.STATE_READY:
            raise RuntimeError("Protocol not (yet) ready!")
        if self._used:
            raise RuntimeError("Protocols are one-time-use only!")
        self._used = True
        self._cipher = self._get_cipher()
        self.sendString(constants.ACTION_SET + path)
        self._state = self.STATE_SENDING
        rv = yield self._write_async_loop(fin)
        returnValue(rv)

    @inlineCallbacks
    def _write_async_loop(self, fin):
        """write data from fin to connection."""
        self._cipher = self._get_cipher()
        while True:
            data = yield threads.deferToThread(self._read_from_f, fin)
            if not data:
                break
            yield self.sendString(data)
        self.transport.loseConnection()

    def _read_from_f(self, fin):
        """read from fin and return the content encrypted."""
        data = fin.read(constants.DEFAULT_CLIENT_READ_SIZE)
        if not data:
            return data
        if self._cipher is not None:
            return self._cipher.encrypt(data)
        else:
            return data

    def on_error(self, msg):
        """called when there was an error."""
        pass

    def on_version_mismatch(self):
        """called when the version check fails."""
        if self._d is not None:
            self._d.errback(VersionError("Server and client use different communication protocol versions!"))

    def on_auth_fail(self):
        """called when the authentication fails."""
        if self._d is not None:
            self._d.errback(AuthenticationError("Authentication failed!"))


@implementer(ICryptarchiveClient)
class CryptarchiveTxClient(object):
    """The client for the cryptoarchive."""
    def __init__(self, host, username, password, port=constants.DEFAULT_PORT, hash_password=True):
        self._username = username
        if hash_password:
            self._password = hashlib.sha256(password).digest()
        else:
            self._password = password
        self._host = host
        self._port = port
        self.reactor = reactor
        self._index = None

    @inlineCallbacks
    def new_connection(self):
        """return a new connection."""
        d = Deferred()
        proto = CryptarchiveClientProtocol(self._username, self._password, d=d)
        ep = endpoints.TCP4ClientEndpoint(self.reactor, self._host, self._port)
        endpoints.connectProtocol(ep, proto)
        cp = yield d
        returnValue(cp)

    @inlineCallbacks
    def retrieve_index(self):
        """retrieves the index."""
        conn = yield self.new_connection()
        f = StringIO.StringIO()
        try:
            yield conn.get_file(constants.INDEX_FILE_NAME, f.write)
        except FileNotFound:
            self._index = Index.new()
            yield self.save_index()
        else:
            ic = f.getvalue()
            self._index = Index.loads(ic)

    @inlineCallbacks
    def save_index(self):
        """save the index to the server."""
        conn = yield self.new_connection()
        dumped = self._index.dumps()
        sio = StringIO.StringIO(dumped)
        yield conn.set_file(constants.INDEX_FILE_NAME, sio)

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

    @inlineCallbacks
    def mkdir(self, path):
        """creates a new directory at path."""
        if self._index is None:
            raise RuntimeError("Index not yet retrieved!")
        if self._index.dir_exists(path):
            raise ValueError("Directory already exists!")
        self._index.mkdir(path)
        yield self.save_index()

    @inlineCallbacks
    def upload(self, f, dest):
        """upload a file."""
        if self._index is None:
            raise RuntimeError("Index not yet retrieved!")
        fid = self._index.create_file(dest)
        conn = yield self.new_connection()
        yield conn.set_file(fid, f)
        yield self.save_index()

    @inlineCallbacks
    def download(self, path, f):
        """download a file."""
        if self._index is None:
            raise RuntimeError("Index not yet retrieved!")
        fid = self._index.get_file_id(path)
        conn = yield self.new_connection()
        yield conn.get_file(fid, f.write)

    @inlineCallbacks
    def delete(self, path):
        """delete a file:"""
        if self._index is None:
            raise RuntimeError("Index not yet retrieved!")
        removed = self._index.remove_from_index(path)
        for fid in removed:
            conn = yield self.new_connection()
            yield conn.delete_file(fid)
        yield self.save_index()
