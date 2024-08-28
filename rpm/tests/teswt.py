import threading, itertools, traceback, multiprocessing, sys, logging, logging.handlers, os, functools, operator, stat, requests, base64, ssl, time, yaml, array, cython
from kubernetes import client, config, watch
from contextlib import suppress
from subprocess import Popen, PIPE
from lxml import etree
from re import search, sub, compile
from pathlib import Path
from queue import Queue
from permissions_change_module.permissions_change import change_group_permissions
from permissions_change_module.permissions_change import change_permissions
from yaml import SafeLoader
import xmltodict
from http.server import BaseHTTPRequestHandler, HTTPServer
from hashlib import sha256
from OpenSSL import crypto, SSL
from random import randint
import warnings 
import urllib
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
IS_DIR = 0o040000
IS_FILE = 0o100000
def is_valid_path(input_path, mode=IS_FILE):
    """Check if the input string matches a regex and
        file mode and returns true"""
    regex = (
        r"^(?:\/|file:[\/|\\][\/|\\][\/|\\]?)?(([a-zA-Z0-9_ \-])"
        + r"\:|\\\\[a-zA-Z0-9_ -]+[\\|\/][a-zA-Z0-9_ \-]+)?([\/|\\]"
        + r"(?!CON|PRN|AUX|NUL|CONIN|CONOUT|COM|LPT)[a-zA-Z0-9_ .\-]+)+$"
    )
    print(input_path)
    with suppress(Exception):
        return (
            bool(search(regex, input_path))
            and os.stat(input_path).st_mode & 0o170000 == mode
        )
if is_valid_path("/etc/opt/ericsson/ericmodeldeployment/models/etc/model/2023-03-21_20-05-37", IS_DIR):
    print("valid")
else:
    print("invalid")