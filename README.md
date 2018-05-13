# Cryptarchive
*Encrypted network storage*
# Features
- standalone server
- client libraries for socket and twisted
- no cleartext usernames stored (usernames are stored hashed)
- auth-challenge makes password transfer to server unneccessary (challenge will be solved localy)
- filenames and directory sturcture are stored in an encrypted file.
- command line tool

# Installation

*`sudo` may be required.*

**From pypi:**
```bash
pip install cryptarchive
```

**From source:**
```bash
git clone https://github.com/bennr01/cryptarchive.git
cd cryptarchive
python setup.py install
```

# Server
To start the server, run `cryptarchive-server <datadir>`
For more arguments, please see `cryptarchive-server --help`.

# Client
To view help on the command-line client, see `cryptarchive-client --help`.
