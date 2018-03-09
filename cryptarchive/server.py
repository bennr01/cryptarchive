"""cryptarchive server"""
import hashlib

from twisted.internet import threads
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.protocol import Factory
from twisted.protocols.basic import IntNStringReceiver
from twisted.python.filepath import FilePath

from cryptarchive.challenge import Challenge
from cryptarchive import constants



class CryptarchiveServerProtocol(IntNStringReceiver):
    """
    The Protocol for the cryptarchive server.
    For security reasons, each protocol instance is one-user only.
    """
    structFormat = constants.MESSAGE_LENGTH_PREFIX
    prefixLength = constants.MESSAGE_LENGTH_PREFIX_LENGTH
    MAX_LENGTH = constants.MAX_MESSAGE_LENGTH

    # state constants
    STATE_IGNORE = 0
    STATE_WAIT_VERSION = 5
    STATE_WAIT_USERNAME = 1
    STATE_WAIT_CHALLENGE_RESPONSE = 2
    STATE_READY = 3
    STATE_WRITING = 4

    def connectionMade(self):
        self.state = self.STATE_WAIT_VERSION
        self.userid = None
        self.challenge = None
        self.cur_f = None
        IntNStringReceiver.connectionMade(self)

    @inlineCallbacks
    def stringReceived(self, s):
        """called when a string was received."""
        if len(s) == 0:
            # ignore message
            pass

        if self.state == self.STATE_IGNORE:
            # ignore message
            pass

        elif self.state == self.STATE_WAIT_VERSION:
            if s != constants.COM_VERSION:
                self.sendString("VERSION-FAIL")
                self.transport.loseConnection()
            else:
                self.state = self.STATE_WAIT_USERNAME
                self.sendString("VERSION-OK")

        elif self.state == self.STATE_WAIT_USERNAME:
            # username received
            self.userid = self.factory.get_userid(s)
            # send challenge
            self.challenge = yield self.factory.get_challenge(self.userid)
            ser = self.challenge.dumps()
            self.state = self.STATE_WAIT_CHALLENGE_RESPONSE
            self.sendString(ser)

        elif self.state == self.STATE_WAIT_CHALLENGE_RESPONSE:
            valid = self.challenge.check_solution(s)
            if valid:
                self.state = self.STATE_READY
                self.sendString("AUTH-OK")
            else:
                self.state = self.STATE_IGNORE
                self.sendString("AUTH-FAIL")
                self.transport.loseConnection()

        elif self.state == self.STATE_READY:
            action, data = s[0], s[1:]

            if action == constants.ACTION_GET:
                p = self.factory.get_file_path(self.userid, data)
                if not p.exists():
                    self.sendString("E")
                else:
                    self.sendString("O")
                    with p.open("rb") as fin:
                        yield self.async_send(fin)
                self.state = self.STATE_IGNORE
                self.transport.loseConnection()

            elif action == constants.ACTION_SET:
                p = self.factory.get_file_path(self.userid, data)
                self.cur_f = p.open("wb")
                self.state = self.STATE_WRITING

            elif action == constants.ACTION_DELETE:
                p = self.factory.get_file_path(self.userid, data)
                if not p.exists:
                    res = constants.RESPONSE_ERROR + "File not found!"
                else:
                    try:
                        p.remove()
                    except Exception as e:
                        res = constants.RESPONSE_ERROR + repr(e)
                    else:
                        res = constants.RESPONSE_OK + "File deleted."
                self.state = self.STATE_IGNORE
                self.sendString(res)
                self.transport.loseConnection()

            else:
                self.transport.loseConnection()

        elif self.state == self.STATE_WRITING:
            self.cur_f.write(s)

        else:
            self.transport.loseConnection()
            raise RuntimeError("Logic Error: reached invalid state!")

    def connectionLost(self, reason):
        """called when the connection was lost."""
        if self.cur_f is not None:
            self.cur_f.close()
            self.cur_f = None
        IntNStringReceiver.connectionLost(self, reason)

    @inlineCallbacks
    def async_send(self, fin):
        """
        Send file asynchroneous.
        :param fin: file to read
        :type fin: file
        :return: deferred which will be called when finished
        :rtype: Deferred
        """
        while True:
            n = 32 * 1024  # 32 KB
            data = yield threads.deferToThread(fin.read, n)
            if not data:
                break
            self.sendString(data)


class CryptarchiveServerFactory(Factory):
    """
    Factory for the cryptarchive server.
    :param path: path where the files will be stored.
    :type path: str or FilePath
    """
    protocol = CryptarchiveServerProtocol

    def __init__(self, path):
        if isinstance(path, FilePath):
            self.path = path
        else:
            self.path = FilePath(path)

    def buildProtocol(self, addr):
        """build a protocol for the communication with the client"""
        p = self.protocol()
        p.factory = self
        return p

    def get_userid(self, username):
        """
        Return the userid for the username.
        :param username: the username of the user
        :type username: str
        :return: the userid of the user
        :rtype: str
        """
        return "u_" + hashlib.sha256(username).hexdigest()


    def get_user_path(self, userid):
        """
        Return the path of the user.
        :param userid: the id of the user
        :type userid: str
        :return: the path of the user
        :rtype: FilePath
        """
        return self.path.child(userid)

    def user_exists(self, userid):
        """
        Check if the user exist.
        :param userid: the userid of the user
        :type userid: str
        :return: whether the user exists or not
        :rtype: bool
        """
        return self.get_user_path(userid).exists()

    def user_is_setup(self, userid):
        """
        Check if the user account is setup.
        :param userid: the userid of the user
        :type userid: str
        :return: whether the user has been setup or not
        :rtype: bool
        """
        up = self.get_user_path(userid)
        abe = up.child("authblock.bin").exists()
        hfe = up.child("hash.bin").exists()
        return (abe and hfe)

    @inlineCallbacks
    def get_challenge(self, userid):
        """returns a challenge for the user."""
        if self.user_exists(userid):
            authblockpath = self.get_authblock_path(userid)
            hash_path = self.get_hash_path(userid)
            authblock = yield self.load_file_in_thread(authblockpath)
            expected_hash = yield self.load_file_in_thread(hash_path)
            returnValue(Challenge.generate_challenge(authblock, expected_hash))
        else:
            returnValue(Challenge.generate_unsolvable_challenge())

    def get_file_path(self, userid, filename):
        """
        Return the path of the file of the user.
        :param userid: userid of the user
        :type userid: str
        :param filename: name of the file
        :type filename: str
        :return: the path of the file.
        :rtype: FilePath
        """
        up = self.get_user_path(userid)
        fp = up.child(filename)
        return fp

    def get_authblock_path(self, userid):
        """
        Return the path of the authblock file of the user.
        :param userid: userid of the user
        :type userid: str
        :return: the path of the authblock file.
        :rtype: FilePath
        """
        return self.get_file_path(userid, "authblock.bin")

    def get_hash_path(self, userid):
        """
        Return the path of the hash file of the user.
        :param userid: userid of the user
        :type userid: str
        :return: the path of the hash file.
        :rtype: FilePath
        """
        return self.get_file_path(userid, "hash.bin")

    def load_file_in_thread(self, path):
        """
        Load the specified file in a thread.
        :param path: the path of the file to load
        :type path: FilePath
        :return: a deferred which will be called with the file content
        :rtype: Deferred
        """
        return threads.deferToThread(path.getContent)
