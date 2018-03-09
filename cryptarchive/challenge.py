"""auth challenges"""
import hashlib
import base64
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter

from cryptarchive.constants import DEFAULT_AUTHBLOCK_SIZE


# =========== AUTH-CHALLENGE ===========
# REQUIREMENTS:
#    - never send the key directly over the network
#    - require custom challenge for every connection
#
# IDEA:
#    CLIENT -> SERVER: connect with username
#    SERVER -> CLIENT:
#        IF username EXISTS:
#            static auth data and one-time code
#        ELSE:
#            random data and random one-time code
#    CLIENT:
#        1. AES chipher decrypt random data
#        2. hash result from client step 1
#        3. hash (result from client step 2 + one-time code)
#    CLIENT -> SERVER: result from client step 3
#    SERVER:
#        1. load hash of decrypted data
#        2. hash (hash + one-time code)
#        3. compare with client response



class Challenge(object):
    """
    An Auth challenger.
    See comment above in sourcecode to view description of the process.
    Main constructor is generate_challenge
    """

    def __init__(self, authblock, otc, expected=None):
        self._authblock = authblock
        self._otc = otc
        self._expected = expected

    @classmethod
    def generate_challenge(cls, authblock, expected_hash):
        """
        Generate an auth challenge.
        :param authblock: data the client has to decrypt
        :type authblock: str
        :param expected_hash: the hash of the correctly decrypted authblock
        :return: the Challenge
        :rtype: instance of cls
        """
        otc = get_random_bytes(32)
        return cls(authblock, otc, expected_hash)

    @classmethod
    def generate_unsolvable_challenge(cls):
        """
        Generate an unsolvable auth challenge.
        :return: an unsolvable auth challenge
        :rtype: instance of cls
        """
        authblock = get_random_bytes(DEFAULT_AUTHBLOCK_SIZE)
        return cls.generate_challenge(authblock, expected_hash=None)

    @staticmethod
    def generate_authblock_and_hash(password, authblock_size=DEFAULT_AUTHBLOCK_SIZE, hash_password=True):
        """
        Generate a new authblock with the corresponding hash.
        :param password: password of the user to create authblock for
        :type password: str
        :param authblock_size: the size of the authblock.
        :type authblock_size: int
        :param hash_password: whether to hash the password before using or not
        :type hash_password: boolean
        :return: (authblock, hash)
        :rtype: tuple of (str, str)
        """
        if hash_password:
            key = hashlib.sha256(password).digest()
        else:
            key = password
        authblock = get_random_bytes(authblock_size)
        hash = hashlib.sha256(authblock).digest()
        cipher = AES.new(key, mode=AES.MODE_CTR, counter=Counter.new(128))
        enc = cipher.encrypt(authblock)
        return (enc, hash)

    def solve(self, key):
        """
        Solve the authchallenge.
        :param key: the key/password to use
        :type key: str
        :return: the solution of the challenge
        :rtype: str
        """
        assert len(key) == 32
        cipher = AES.new(key, mode=AES.MODE_CTR, counter=Counter.new(128))
        dec = cipher.decrypt(self._authblock)
        dechash = hashlib.sha256(dec).digest()
        res = hashlib.sha256(dechash + self._otc).hexdigest()
        return res

    def check_solution(self, solution):
        """
        Check the solution.
        :param solution: the solution to check
        :type solution: str
        :return: whether the solution is valid.
        :rtype: bool
        """
        if self._expected is None:
            return False
        eh = hashlib.sha256(self._expected + self._otc).hexdigest()
        return solution == eh

    def dumps(self):
        """
        Serialize this challenge for network transit.
        For security reasons, the result does not contain the expected_hash.
        :return: a string which can be used to recreate this challenge.
        :rtype: str
        """
        raw = {
            "authblock": base64.b64encode(self._authblock),
            "otc": base64.b64encode(self._otc),
            "expected": None,
        }
        dumped = json.dumps(raw)
        return dumped

    @classmethod
    def loads(cls, s):
        """
        Load a challenge from a string.
        :param s: the serialized data of this challenge.
        :type s: str
        :return: the challenge
        :rtype: instance of cls
        """
        loaded = json.loads(s)
        authblock = base64.b64decode(loaded["authblock"])
        otc = base64.b64decode(loaded["otc"])
        return cls(authblock, otc)

