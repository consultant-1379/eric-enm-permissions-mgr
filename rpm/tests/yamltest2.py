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
from permissions_change_module.permissions_change import change_group_permissions
from permissions_change_module.permissions_change import change_permissions
from yaml import SafeLoader
import xmltodict
from http.server import BaseHTTPRequestHandler, HTTPServer
from hashlib import sha256
from OpenSSL import crypto, SSL
from random import randint
import urllib

def parse_file_as_tree(filepath):
    try:
        file_ext = Path(filepath).suffix
        if file_ext == ".xml":
            parser = etree.XMLParser(remove_blank_text=True)
            return etree.parse(filepath, parser)
        elif file_ext == ".yaml":
            yaml_file=open(filepath,"r")
            yaml_string=yaml.load(yaml_file,Loader=SafeLoader)
            xml_string=xmltodict.unparse(yaml_string)
            xml_string=xml_string.replace("<breakpoint><-id>", "<breakpoint id=\"")
            xml_string=xml_string.replace("</-id><-type>", "\" type=\"")
            xml_string=xml_string.replace("</-type><-with>", "\" with=\"")
            xml_string=xml_string.replace("<-with>", "\" with=\"")
            xml_string=xml_string.replace("</-type>", "\">")
            xml_string=xml_string.replace("</-with>", "\">")
            print(xml_string)
            return etree.ElementTree(etree.fromstring(xml_string.encode('ascii')))
    except Exception as e:
        print(e)
        exit(-1)import re

name = 'CamelCaseName'
name = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
print(name)

print(parse_file_as_tree("pom.yaml"))