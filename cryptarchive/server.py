"""cryptarchive server"""
from twisted.internet import threads
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.protocol import Factory
from twisted.protocols.basic import IntNStringReceiver

from cryptarchive.challenge import Challenge
from cryptarchive import constants
from cryptarchive.usermanager import UserManager



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
            self.userid = self.factory.usermanager.get_userid(s)
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
                p = self.factory.usermanager.get_file_path(self.userid, data)
                if not p.exists():
                    self.sendString("E")
                else:
                    self.sendString("O")
                    with p.open("rb") as fin:
                        yield self.async_send(fin)
                self.state = self.STATE_IGNORE
                self.transport.loseConnection()

            elif action == constants.ACTION_SET:
                p = self.factory.usermanager.get_file_path(self.userid, data)
                self.cur_f = p.open("wb")
                self.state = self.STATE_WRITING

            elif action == constants.ACTION_DELETE:
                p = self.factory.usermanager.get_file_path(self.userid, data)
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

    def lengthLimitExceeded(self, length):
        """called when the length limit is exceeded."""
        if self.factory.verbose:
            print "WARNING: Message length exceeds self.MAX_LENGTH: " + str(length)
        self.transport.loseConnection()


class CryptarchiveServerFactory(Factory):
    """
    Factory for the cryptarchive server.
    :param path: path where the files will be stored.
    :type path: str or FilePath
    """
    protocol = CryptarchiveServerProtocol

    def __init__(self, path, verbose=False):
        self.verbose = verbose
        self.usermanager = UserManager(path)

    def buildProtocol(self, addr):
        """build a protocol for the communication with the client"""
        p = self.protocol()
        p.factory = self
        return p

    @inlineCallbacks
    def get_challenge(self, userid):
        """returns a challenge for the user."""
        if self.usermanager.user_exists(userid):
            authblockpath = self.usermanager.get_authblock_path(userid)
            hash_path = self.usermanager.get_hash_path(userid)
            authblock = yield self.load_file_in_thread(authblockpath)
            expected_hash = yield self.load_file_in_thread(hash_path)
            returnValue(Challenge.generate_challenge(authblock, expected_hash))
        else:
            returnValue(Challenge.generate_unsolvable_challenge())

    def load_file_in_thread(self, path):
        """
        Load the specified file in a thread.
        :param path: the path of the file to load
        :type path: FilePath
        :return: a deferred which will be called with the file content
        :rtype: Deferred
        """
        return threads.deferToThread(path.getContent)
