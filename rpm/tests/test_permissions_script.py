import unittest
import warnings 
warnings.filterwarnings(action='ignore',message='Python 3.6 is no longer supported*')
import threading, itertools, traceback, multiprocessing, sys, logging, logging.handlers, os, functools, operator, stat, requests, base64, ssl, time, yaml, array, cython
from kubernetes import client, config, watch
from contextlib import suppress
from subprocess import Popen, PIPE
from lxml import etree
from re import search, sub, compile
from pathlib import Path
from queue import Queue
from yaml import SafeLoader
import xmltodict
from http.server import BaseHTTPRequestHandler, HTTPServer
from hashlib import sha256
from OpenSSL import crypto, SSL
from random import randint
import urllib
import pytest
from pathlib import Path

test_config_directory = "../tests/testconfig/"
os.chdir('src')
class testPermissionsScripts(unittest.TestCase):
    def setup_method(self, test_method):
        print("Setting up tests")
        print(os.getcwd())
        
        #creating a new directory called pythondirectory
        Path("foo/foobar/baz").mkdir(parents=True, exist_ok=True)
        Path('foo/test').touch()
        Path('foo/test2').touch()
        Path('foo/test3').touch()
        Path('foo/test.txt').touch()
        Path('foo/test2.sh').touch()
        Path('foo/test3.xml').touch()
        # configure self.attribute


    def test_parse_file_as_tree(self):
        from permissions_script import parse_file_as_tree
        print(etree.tostring(parse_file_as_tree(test_config_directory + "pom.yaml"), encoding='unicode', method='xml'))
        
        # assert '<breakpoint id="3" type="ls" with="1">' in parse_file_as_tree(test_config_directory + "pom.yaml")
        # actual = 
        # expected = 
        # self.assertEqual(actual, expected)

    # def test_permissions_change_module(self):
    #     from permissions_change_module.permissions_change import change_group_permissions
    #     a=array.array('i', [205,306])
    #     change_group_permissions(b"foo", a)