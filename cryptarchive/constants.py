"""constants for the crypt archive."""
import struct

DEFAULT_AUTHBLOCK_SIZE = 4096  # 4kb

MESSAGE_LENGTH_PREFIX = "!I"
MESSAGE_LENGTH_PREFIX_LENGTH = struct.calcsize(MESSAGE_LENGTH_PREFIX)
MAX_MESSAGE_LENGTH = 130 * 1024  # 130 KB

ACTION_GET = "G"
ACTION_SET = "S"
ACTION_DELETE = "D"

RESPONSE_OK = "O"
RESPONSE_ERROR = "E"

DEFAULT_PORT = 45654
COM_VERSION = "0.0.1"

DEFAULT_CLIENT_READ_SIZE = 128 * 1024  # 128 KB

INDEX_FILE_NAME = "index.bin"
INDEX_ENCODING = "utf-8"