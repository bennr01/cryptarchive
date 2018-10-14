"""interface definitions."""
from zope.interface import Interface, Attribute

from cryptarchive import constants


class ICryptarchiveClient(Interface):
    """The interface for the client for the cryptoarchive."""

    _index = Attribute("The Index")

    def __init__(self, host, username, password, port=constants.DEFAULT_PORT, hash_password=True):
        pass

    def retrieve_index(self):
        """
        Retrieves the index and sets self._index.
        """
        pass

    def save_index(self):
        """
        Save self._index to the server.
        """
        pass

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
        """creates a new directory at path and save the index."""
        pass

    def upload(self, f, dest):
        """upload a file and save the index."""
        pass

    def download(self, path, f):
        """download a file."""
        pass

    def delete(self, path):
        """delete a file and save the index."""
        pass

    def move(self, src, dest):
        """move the path src to dest."""
        pass
