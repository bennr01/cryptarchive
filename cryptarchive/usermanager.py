"""the user manager for the server."""
import hashlib

from twisted.python.filepath import FilePath


class UserManager(object):
    """
    The UserManager manages the user paths.
    :param path: path where the files will be stored.
    :type path: str or FilePath
    """
    def __init__(self, path):
        if isinstance(path, FilePath):
            self.path = path
        else:
            self.path = FilePath(path)

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

