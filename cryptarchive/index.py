"""index file manager."""
import hashlib
import os
import json

from cryptarchive import constants
from cryptarchive.errors import FileNotFound


# ============ INDEX FORMAT =================
# as json:
# {
#   "dirs": {
#           name: {
#                   name: {
#                       "name": childname,
#                       "isdir": isdir,
#                       "id": id,
#                       }
#                  }
#           ...
#           },
# }


class Index(object):
    """An Index file manager"""
    def __init__(self, indexdata):
        self._index = indexdata

    @classmethod
    def new(cls):
        """create a new index."""
        indexdata = {
            "dirs": {
                "/": {
                    },
                },
            }
        return cls(indexdata)

    @classmethod
    def loads(cls, data):
        """
        Load the Index from data.
        :param data: data to load from
        :type data: str
        :return: cls loaded from data
        :rtype: instance of cls
        """
        content = json.loads(data)
        return cls(content)

    def dumps(self):
        """
        Serializes this index.
        :return: serialized data of this Index
        :rtype: str
        """
        return json.dumps(self._index)

    def mkdir(self, path):
        """
        Create a directory.
        :param path: virtual path to create
        :type path: str
        """
        path = self.normalize_dir_path(path)
        if self.dir_exists(path):
            return
        parent = self.normalize_dir_path(os.path.dirname(os.path.dirname(path)))
        if parent in ("/", "\\", ""):
            parent = "/"
        if (not self.dir_exists(parent)) and (parent is not None):
            self.mkdir(parent)
        self._index["dirs"][path] = {}
        if parent is not None:
            self._index["dirs"][parent][path] = {
                "name": os.path.basename(os.path.dirname(path)),
                "isdir": True,
                "id": path,
                }

    def dir_exists(self, path):
        """
        check if the directory exists.
        :param path: path to check
        :type path: str
        :return: wether the path exists or not
        :rtype: boolean
        """
        path = self.normalize_dir_path(path)
        if path in ("/", "", "\\"):
            return True
        return (path in self._index["dirs"])

    def file_exists(self, path):
        """
        Check if the file exists.
        :param path: path to check
        :type path: str
        :return: wether the path exists or not
        :rtype: boolean
        """
        parent = self.normalize_dir_path(os.path.dirname(path))
        path = self.normalize_file_path(path)
        fn = os.path.basename(path)
        if parent not in self._index["dirs"]:
            return False
        if fn in self._index["dirs"][parent]:
            return True
        else:
            return False

    def listdir(self, path):
        """
        Returns the content of the given path.
        :param path: path to list
        :type path: str
        :return: [(name, isdir) of each file]
        :rtype: list of tuples of (str, bool)
        """
        path = self.normalize_dir_path(path)
        if path not in self._index["dirs"]:
            return []
        ret = []
        for name in self._index["dirs"][path]:
            data = self._index["dirs"][path][name]
            ret.append((data["name"], data["isdir"]))
        return ret

    def create_file(self, path):
        """
        Create a new file.
        Return the file id.
        :param path: virtual path of the new file
        :type path: str
        :return: the new file id
        :rtype: str
        """
        path = self.normalize_file_path(path)
        if self.file_exists(path):
            return self.get_file_id(path)
        parent = self.normalize_dir_path(os.path.dirname(path))
        if not self.dir_exists(parent):
            self.mkdir(parent)
        fid = self.new_file_id(parent, path)
        self._index["dirs"][parent][path] = {
            "name": os.path.basename(path),
            "isdir": False,
            "id": fid,
            }
        return fid

    def remove_from_index(self, path):
        """
        Remove path from the index.
        :param path: virtual path to remove from the index.
        :type path: str
        :return: list of removed fileids
        :rtype: list of str
        """
        removed = []
        normalized = self.normalize_dir_path(path)
        # if path is a directory, remove all children
        if normalized in list(self._index["dirs"]):
            for child in list(self._index["dirs"][normalized]):
                removed += self.remove_from_index(child)
        # remove all references to path
        for dn in self._index["dirs"]:
            dircontent = self._index["dirs"][dn]
            for sp in dircontent.keys():
                fid = self._index["dirs"][dn][sp]["id"]
                isdir = self._index["dirs"][dn][sp]["isdir"]
                if (sp == path) or (fid == path):
                    if not isdir:
                        removed.append(fid)
                    del self._index["dirs"][dn][sp]
        return [self._encode(e) for e in removed]

    def new_file_id(self, parentdir, name):
        """
        Generate a new file id.
        :param parentdir: the parent directory
        :type parentdir: str
        :param name: the filename
        :type name: str
        :return: the generated file id
        :rtype: str
        """
        parentdir = self.normalize_dir_path(parentdir)
        fid = hashlib.sha256(parentdir + name).hexdigest()
        return fid

    def get_file_id(self, path):
        """
        Return the file id for the file at path.
        :param path: path to get fileid for
        :type path: str
        :return: the fileid of path
        :rtype: str
        """
        parent = self.normalize_dir_path(os.path.dirname(path))
        path = self.normalize_file_path(path)
        if parent not in self._index["dirs"]:
            raise FileNotFound("No such directory: '{p}'!".format(p=parent))
        if path not in self._index["dirs"][parent]:
            raise FileNotFound("No such File: '{p}'!".format(p=path))
        else:
            return self._encode(self._index["dirs"][parent][path]["id"])

    def _encode(self, s):
        """
        Encode s into the index encoding.
        :param s: string to encode
        :type s: str or unicode
        :return: encoded string
        :rtype: str
        """
        if isinstance(s, str):
            return s
        elif isinstance(s, unicode):
            return s.encode(constants.INDEX_ENCODING)
        else:
            raise TypeError("Expected string or unicode, got {t}".format(t=type(s)))

    def normalize_dir_path(self, path):
        """
        Return a normalized directory path.
        Example:
        /test/   -> /test/
        /test    -> /test/
        /test//  -> /test/
        test/    -> /test/
        \\test\\ -> /test/

        :param path: path to normalize
        :type path: str
        :return: the normalized path
        :rtype: str
        """
        # 1. ensure final slash
        path = os.path.join(*os.path.split(path))
        if not path.endswith(os.sep):  # sep will be converted later
            path += os.sep
        # 2. always use '/' as seperator
        path = path.replace(os.path.sep, "/")
        # 3. remove multi slashes
        while "//" in path:
            path = path.replace("//", "/")
        # 4.ensure root is "/":
        if len(path) == 0:
            path = "/"
        # 5. ensure start slash
        if not path.startswith("/"):
            path = "/" + path
        return path

    def normalize_file_path(self, path):
        """
        Return a normalized file path.
        Example:
        /test/file.txt   -> /test/file.txt
        /test//file.txt  -> /test/file.txt
        test/file.txt    -> /test/file.txt
        \\test\\file.txt -> /test/file.txt

        :param path: path to normalize
        :type path: str
        :return: the normalized path
        :rtype: str
        """
        # 1. always use '/' as seperator
        path = path.replace(os.path.sep, "/")
        # 2. remove multi slashes
        while "//" in path:
            path = path.replace("//", "/")
        # 3. ensure start slash
        if not path.startswith("/"):
            path = "/" + path
        return path
