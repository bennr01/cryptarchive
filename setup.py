"""setup.py for cryptarchive"""

from setuptools import setup


setup(
    name="cryptarchive",
    version="0.1.0",
    author="bennr01",
    author_email="benjamin99.vogt@web.de",
    description="encrypted storage server and client",
    long_description=open("README.md").read(),
    license="AGPLv3",
    keywords="crypto server data storage network CLI",
    url="https://github.com/bennr01/cryptarchive/",
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python",
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        ],
    packages=[
        "cryptarchive",
        ],
    install_requires=[
        "twisted",
        "pycryptodome",
        "zope.interface",
        ],
    entry_points={
        "console_scripts": [
            "cryptarchive-server=cryptarchive.runner:server_main",
            "cryptarchive-client=cryptarchive.runner:client_main",
        ],
    }
    )
