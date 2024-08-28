#!python
#cython: language_level=3
##########################################################################
# COPYRIGHT Ericsson 2023
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
###########################################################################
import warnings 
warnings.filterwarnings(action='ignore',message='Python 3.6 is no longer supported*')
# warnings.filterwarnings(action='ignore',message='Logged from file (unknown file)*')


import socket # For gethostbyaddr()
import re, threading, traceback, sys, logging, logging.handlers, os, functools, operator, stat, requests, base64, ssl, time, yaml, array, cython
from kubernetes import client, config
from contextlib import suppress
from subprocess import PIPE, call
from lxml import etree
from re import search, sub
from pathlib import Path
from permissions_change_module.permissions_change import change_group_permissions
from permissions_change_module.permissions_change import change_permissions
from permissions_change_module.permissions_change import directory_counter
from permissions_change_module.permissions_change import file_counter
from yaml import SafeLoader
import xmltodict
from hashlib import sha256
from OpenSSL import crypto, SSL
from random import randint
import urllib
import shutil
import time
import urllib.parse
import textwrap
from logging.handlers import SocketHandler
import traceback
import socket
from datetime import datetime
try:
    import json
except ImportError:
    import simplejson as json

permissions_logger = logging.getLogger('permissions_logger')
permissions_logger.setLevel(logging.INFO)
permissions_logger.addHandler(logging.StreamHandler(sys.stdout))
pods = []
termination_block = True
UPPER_FOLLOWED_BY_LOWER_RE = re.compile('(.)([A-Z][a-z]+)')
LOWER_OR_NUM_FOLLOWED_BY_UPPER_RE = re.compile('([a-z0-9])([A-Z])')
camelCase=re.compile(r'(?<!^)(?=[A-Z])') # finds camel case names


class LogstashFormatter(logging.Formatter):

    def __init__(self, message_type='Logstash', tags=None, fqdn=False):
        self.message_type = message_type
        self.tags = tags if tags is not None else []

        if fqdn:
            self.host = socket.getfqdn()
        else:
            self.host = socket.gethostname()

    def get_extra_fields(self, record):
        # The list contains all the attributes listed in
        # http://docs.python.org/library/logging.html#logrecord-attributes
        skip_list = (
            'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
            'funcName', 'id', 'levelname', 'levelno', 'lineno', 'module',
            'msecs', 'msecs', 'message', 'msg', 'name', 'pathname', 'process',
            'processName', 'relativeCreated', 'thread', 'threadName', 'extra',
            'auth_token', 'password', 'stack_info')

        if sys.version_info < (3, 0):
            easy_types = (basestring, bool, dict, float, int, long, list, type(None))
        else:
            easy_types = (str, bool, dict, float, int, list, type(None))

        fields = {}

        for key, value in record.__dict__.items():
            if key not in skip_list:
                if isinstance(value, easy_types):
                    fields[key] = value
                else:
                    fields[key] = repr(value)

        return fields

    def get_debug_fields(self, record):
        fields = {
            'stack_trace': self.format_exception(record.exc_info),
            'lineno': record.lineno,
            'process': record.process,
            'thread_name': record.threadName,
        }

        # funcName was added in 2.5
        if not getattr(record, 'funcName', None):
            fields['funcName'] = record.funcName

        # processName was added in 2.6
        if not getattr(record, 'processName', None):
            fields['processName'] = record.processName

        return fields

    @classmethod
    def format_source(cls, message_type, host, path):
        return "%s://%s/%s" % (message_type, host, path)

    @classmethod
    def format_timestamp(cls, time):
        tstamp = datetime.utcfromtimestamp(time)
        return tstamp.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (tstamp.microsecond / 1000) + "Z"

    @classmethod
    def format_exception(cls, exc_info):
        return ''.join(traceback.format_exception(*exc_info)) if exc_info else ''

    @classmethod
    def serialize(cls, message):
        if sys.version_info < (3, 0):
            return json.dumps(message)
        else:
            return bytes(json.dumps(message, default=str), 'utf-8')
    
    def format(self, record):
        # Create message dict
        message = {
            '@timestamp': self.format_timestamp(record.created),
            '@version': '1',
            'message': record.getMessage(),
            'host': self.host,
            'path': record.pathname,
            'tags': self.tags,
            'type': self.message_type,

            # Extra Fields
            'level': record.levelname,
            'logger_name': record.name,
        }

        # Add extra fields
        message.update(self.get_extra_fields(record))

        # If exception, add debug info
        if record.exc_info:
            message.update(self.get_debug_fields(record))

        return self.serialize(message)

class LogstashHandler(SocketHandler, object):
    """
    :param host: The host of the logstash server.
    :param port: The port of the logstash server (default 5025).
    :param message_type: The type of the message (default logstash).
    :param fqdn; Indicates whether to show fully qualified domain name or not (default False).
    :param version: version of logstash event schema (default is 0).
    :param tags: list of tags for a logger (default is None).
    """

    def __init__(self, host, port=5025, message_type='logstash', tags=None, fqdn=False):
        super(LogstashHandler, self).__init__(host, port)
        self.formatter = LogstashFormatter(message_type, tags, fqdn)

    def makePickle(self, record):
        return self.formatter.format(record) + b'\n'
    
logstash_logger = logging.getLogger('logstash_logger')
logstash_logger.setLevel(logging.INFO)
logstash_logger.addHandler(LogstashHandler("eric-log-transformer", 5025))
# add extra field to logstash message
logviewer_properties = {
    'program': 'Ericsson Permissions Management Tool',
    'severity': "info",
    'severity_code': "6",
    'facility': "auth",
    'facility_code': "4",
    'pri': "37",
    'tag': "eric-enm-permissions-mgr",
    'originator': "enm-rsyslog"
}

# Breakpoint is a reserved keyword lol need to think of a better name!
class Breakpointe:
    nfs_mount="/ericsson/config_mgt"
    nfs_mount_dir="/ericsson/config_mgt/permenv"
    working_directory_env_map="""
        - name: working_directory_env
          value: {directory_break_point}"""


    mapping_job = """
apiVersion: batch/v1
kind: Job
metadata:
  name: eric-enm-permissions-mgr-task-{claimName}{replica}
  namespace: {namespace}
  labels:
    job: eric-enm-permissions-mgr-task
spec:
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels:
        app: eric-enm-permissions-mgr-task
    spec:
      containers:
      - env:
        - name: run_as_non_root
          value: "true"
        - name: mapping_index
          value: "{mapping_index}"{working_directory_env}{breakpoint_env}
        name: eric-enm-permissions-mgr-task-{claimName}
        image: {image}
        imagePullPolicy: Always
        resources:
          requests:
            cpu: {cpu_request}
            memory: {memory_request}
            ephemeral-storage: {ephemeral_storage_request}
          limits:
            cpu: {cpu_limit}
            memory: {memory_limit}
            ephemeral-storage: {ephemeral_storage_limit}
        securityContext:
          allowPrivilegeEscalation: true{uid}{gid}
          capabilities:
            add:
            - chown
            drop:
            - all
        volumeMounts:
        - mountPath: {directory}
          name: mnt
        - mountPath: "/var/secrets"
          name: eric-enm-permissions-mgr-task-secret
          readOnly: true
        - mountPath: "/var/configmaps"
          name: eric-enm-permissions-mgr-configmap
          readOnly: true
        - mountPath: "/var/configmaps2"
          name: eric-enm-permissions-mgr-filestore-secret
          readOnly: true
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 1
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - eric-enm-permissions-mgr-task
              namespaces:
                - {namespace}
              topologyKey: kubernetes.io/hostname
      restartPolicy: Never
      volumes:
      - name: mnt
        persistentVolumeClaim:
          claimName: {claimName}
      - name: eric-enm-permissions-mgr-task-secret
        secret:
          secretName: eric-enm-permissions-mgr-task-secret
      - name: eric-enm-permissions-mgr-filestore-secret
        secret:
          secretName: eric-enm-permissions-mgr-filestore-secret
      - name: eric-enm-permissions-mgr-configmap
        configMap:
          name: eric-enm-permissions-mgr-configmap
      terminationGracePeriodSeconds: 300
  backoffLimit: 4"""

    def __init__(self):
        self.id=""
        self.directories=[]
        self.breakpoint_directory=""
        self.type=""
        self.breakpoints=[]
        self.parentIndex=0
        self.parent=""


    def add_linked_breakpoint(self, child_breakpointe):
        self.breakpoints.append(child_breakpointe)
        child_breakpointe.parentIndex = self.parentIndex + 1
        child_breakpointe.parent = self

    def run_subcontainer(self, mapping, idx):
        if mapping.run_as_user:
            uid="""
          runAsUser: """+str(mapping.uid)
            gid="""
          runAsGroup: """ + str(mapping.gid)
        else:
            uid, gid = "", ""

        if len(self.breakpoints) == 0:
            breakpoint_env_ = ""
        else:            
            breakpoint_env_="""
        - name: breakpoint_env
          value: \"{breakpoint_env}\"""".format(breakpoint_env=",".join(self.breakpoints))

        for index, bpdirectory in enumerate(self.directories):
            formatted_mapping_job = Breakpointe.mapping_job.format(
                claimName=mapping.claim_name, 
                directory=mapping.directory,
                namespace=mapping.namespace,
                uid=uid,
                gid=gid,
                mapping_index=str(idx),
                working_directory_env=Breakpointe.working_directory_env_map.format(directory_break_point=bpdirectory),
                replica="-"+str(self.id)+"-"+str(index),
                breakpoint_env=breakpoint_env_,
                image=mapping.image,
                cpu_request=mapping.cpu_request,
                memory_request=mapping.memory_request,
                ephemeral_storage_request=mapping.ephemeral_storage_request,
                cpu_limit=mapping.cpu_limit,
                memory_limit=mapping.memory_limit,
                ephemeral_storage_limit=mapping.ephemeral_storage_limit,
            )        

            print(formatted_mapping_job)
            create_from_yaml_single_item(k8s_client, yaml.safe_load(formatted_mapping_job))
            pod = "eric-enm-permissions-mgr-" + str(idx) + "-" + str(bpdirectory)
            pod = urllib.parse.quote(sha256(pod.encode("UTF-8")).hexdigest())
            pods.append("/"+pod)
            print(pods)

    def init_scale_on_kubernetes(self, mapping, idx):
        print("testing==")
        print(self.breakpoint_directory)
        print(self.breakpoints)
        self.allow_ls_on_dir(mapping.directory)
        print("test123")
        if self.type == "ls":
            for file in os.listdir(self.breakpoint_directory):
                current_working_directory = self.breakpoint_directory + "/" + file
                if os.path.isdir(current_working_directory):
                    self.directories.append(current_working_directory)
        elif self.type == "dir":
            self.directories.append(self.breakpoint_directory)
       
        self.run_subcontainer(mapping, idx)
        print(self.directories)

        for breakpointe in self.breakpoints:
            breakpointe.scale_on_kubernetes(mapping, idx)

    def scale_on_kubernetes(self, mapping, idx):
        print("testing==")
        print(self.breakpoint_directory)
        print(self.breakpoints)
            
        if self.breakpoint_directory== "test":
            print("foobar")

        print("self.parent.directories")
        print(self.parent.directories)
        for parent_directory in self.parent.directories:
            self.allow_ls_on_dir(parent_directory)
            current_working_directory = parent_directory + "/" + self.breakpoint_directory
            
            if os.path.isdir(current_working_directory):
                print(current_working_directory)
                if self.type == "ls":
                    for file in os.listdir(current_working_directory):
                        print(file)
                        t = os.path.join(current_working_directory, file)
                        self.directories.append(t)
                elif self.type == "dir":
                    self.directories.append(current_working_directory)
        
        for breakpointe in self.breakpoints:
            breakpointe.scale_on_kubernetes(mapping, idx)
        self.run_subcontainer(mapping, idx)
        
    def allow_ls_on_dir(self, parent_directory):
        x = self.breakpoint_directory.replace(parent_directory,"").split("/")
        if x[0] == "":
            x=x[1:]
        current_working_directory = parent_directory
        for directory in x:
            current_working_directory = current_working_directory + "/" + directory
            if os.path.isdir(current_working_directory):
                os.chown(current_working_directory, os.getuid(), os.getgid())
                st = os.stat(current_working_directory)
                os.chmod(current_working_directory, st.st_mode | stat.S_IXGRP)

    def __repr__(self):
        tab = "" + ((int(self.parentIndex) + 2) * (" "))
        res = "\n"
        res += tab + Mapping.tag("id", self.id)
        res += tab + Mapping.tag("directories", self.directories)
        res += tab + Mapping.tag("breakpoint_directory", self.breakpoint_directory)
        res += tab + Mapping.tag("type", self.type)
        res += tab + Mapping.list_tag("breakpoints", self.breakpoints, self.parentIndex+2)
        return res

class Mapping:

    IS_DIR = 0o040000
    IS_FILE = 0o100000

    # Ensures that the script runs as non root
    # (Warning this does incur a performance penalty)
    run_as_non_root = "True"
    
    run_as_user = "False"
    # Ensures that all mappings run
    # (Useful for debugging or re-running in the case of network failure)
    complete_run = "False"
    # sets the sticky bit for all permissions mappings
    sticky_bit = "False"
    # sets the set gid bit for all permissions mappings
    setgid_bit = "True"
    # sets the set uid bit for all permissions mappings
    setuid_bit = "False"
    # Ensures that group permissions are the same as file permissions
    g_u_bit = "False"
    # ignore user permissions if only group permissions are required
    ignore_user = "False"
    # Special file permissions
    sfp = 0o0000
    # The default directory mode
    default_dirmode = "False"
    # The default filemode
    default_filemode = "False"
    # The default uid (uid) to assign to directories
    default_uid = "306"
    # The default gid (gid) to assign to directories
    default_gid = "207"
    # The default namespace
    namespace = "enm8139"
    # The Webserver hostname
    hostname = "localhost"
    # The webserver port
    server_port = 8443
    # The fsmap index to use
    fsmap_index = "1"
    
    remote_file = '/var/configmaps2/pom.yaml'
    local_file = '/var/configmaps/pom.yaml'

    # default image tag
    image = "armdocker.rnd.ericsson.se/proj_oss_releases/eric-enm-permissions-mgr:inapp_test9"

    # default container resource usage
    cpu_request = "500m"
    memory_request = "500m"
    ephemeral_storage_request = ""

    # default container resource limits
    cpu_limit = "500m"
    memory_limit = "500m"
    ephemeral_storage_limit = ""

    stat_bit_prefix = dict(u = "USR", g = "GRP", o = "OTH")
    chmod_regex = re.compile(r"(?P<who>[uoga]?)(?P<op>[+\-=])(?P<value>[ugo]|[rwx]*)")

    def __init__(self, mapping):
        self.directory = ""
        self.dirmode = False
        self.filemode = False
        self.uid = Mapping.default_uid
        self.gid = Mapping.default_gid
        self.namespace = Mapping.namespace
        self.directory_included = True
        self.recurse_directories = False
        self.claim_name = False
        self.g_u_bit = Mapping.g_u_bit        
        self.setgid_bit = Mapping.setgid_bit
        self.setuid_bit = Mapping.setuid_bit
        self.sticky_bit = Mapping.sticky_bit
        self.image = Mapping.image

        # default container resource usage
        self.cpu_request = Mapping.cpu_request
        self.memory_request = Mapping.memory_request
        self.ephemeral_storage_request = Mapping.ephemeral_storage_request

        # default container resource limits
        self.cpu_limit = Mapping.cpu_limit
        self.memory_limit = Mapping.memory_limit
        self.ephemeral_storage_limit = Mapping.ephemeral_storage_limit

        included = []
        excluded = []
        breakpoints = []
        breakpoints_arr =[]
        file_extensions = ""
        permissions_logger.info("Parsing mapping object")
        
        for item in mapping:
            item.tag = sub(camelCase, '_', item.tag).lower()
            if item.tag == 'dependency':
                for included_excluded in item.getchildren()[0].getchildren():
                    if included_excluded.tag.lower() == "include":
                        included.append(included_excluded.text)
                    elif included_excluded.tag.lower() == "exclude":
                        excluded.append(included_excluded.text)
            elif item.tag == 'breakpoints':
                permissions_logger.info("Parsing Breakpoints")
                for breakpointe in item.getchildren():
                    found=False
                    point = Breakpointe()
                    point.breakpoint_directory = breakpointe.text
                    
                    for att in breakpointe.attrib:
                        if att == "id":
                            while len(breakpoints_arr) <= int(breakpointe.attrib[att]):
                                breakpoints_arr.append([])
                            breakpoints_arr[int(breakpointe.attrib[att])] = point
                            setattr(point, att, breakpointe.attrib[att])
                        elif att == "with":
                            breakpoints_arr[int(breakpointe.attrib[att])].add_linked_breakpoint(point)
                            found=True
                        else:
                            setattr(point, att, breakpointe.attrib[att])
                    if not found:
                        breakpoints.append(point)
                
            elif item.tag == 'filemode' or item.tag == 'dirmode':
                permissions_logger.info("Parsing file or directory mode")
                if item.text.isnumeric():
                    if Mapping.g_u_bit:
                        if len(item.text) == 3:
                            mode = (
                                item.text[:1] +
                                item.text[0] +
                                item.text[2:]
                            )
                            mode = int(mode, 8) | Mapping.sfp
                            setattr(self, item.tag, mode)
                        elif len(item.text) == 4:
                            mode = (
                                item.text[:2] +
                                item.text[1] +
                                item.text[3:]
                            )
                            mode = int(mode, 8) | Mapping.sfp
                            setattr(self, item.tag, mode)
                        else:
                            permissions_logger.info(
                                "Filemode couldn't be parsed correctly" +
                                "acceptable values are 642, 755 etc."
                            )
                else:
                    permissions_logger.error(
                        "Non-nuermic permissions strings not supported"
                    )
                    exit()
            elif item.tag.lower() == 'file_extensions':
                permissions_logger.info("parsing file extensions")
                for file_extension in item.getchildren()[0].getchildren():
                    file_extensions = file_extensions + file_extension.text + ","
            else:
                if item.text.isnumeric():
                    setattr(self, item.tag, int(item.text))
                else:
                    setattr(self, item.tag, item.text)
        self.include = included
        self.breakpoints = breakpoints 
        if "working_directory_env" in os.environ:
            try:
                directory = get_string_property_as_env_preserve_case('working_directory_env', self.directory)
                try:
                    x = directory.split("/")
                    if x[0] == "":
                        x=x[1:]
                    current_working_directory = ""
                    for directory in x:
                        current_working_directory = current_working_directory + "/" + directory
                        if os.path.isdir(current_working_directory):
                            os.chown(current_working_directory, os.getuid(), os.getgid())
                            st = os.stat(current_working_directory)
                            os.chmod(current_working_directory, st.st_mode | stat.S_IXGRP | stat.S_IRGRP)
                except Exception as e:
                    permissions_logger.error("Failed to chmod working directory")
                    permissions_logger.error(current_working_directory)
                    permissions_logger.error(e)
                self.directory = current_working_directory
            except Exception as e:
                permissions_logger.error(
                    "Failed to set the current working directory" + \
                    "please ensure that the directory is correctly mounted and the directory has not been deleted."
                )
                permissions_logger.error(e)

        breakpoint_env = ""
        if "breakpoint_env" in os.environ:
            try:
                breakpoint_env = get_string_property_as_env_preserve_case('breakpoint_env', '')
                permissions_logger.info(f"Setting breakpoint_env: {breakpoint_env}")
            except Exception as e:
                permissions_logger.info("Failed to exclude subdirectories environment variable")
                permissions_logger.info(e)
        
        self.breakpoint_env = breakpoint_env
        self.exclude = (",".join(excluded)).encode('utf-8')
        if len(file_extensions) > 0:
            self.file_extensions = (file_extensions[:len(file_extensions)-1]).encode('utf-8')
        else:
            self.file_extensions = "".encode("utf-8")

    @staticmethod
    @cython.boundscheck(False) # compiler directive
    @cython.wraparound(False) # compiler directive
    def run_chmod_command(directory, filemode):
        # Cython supports compiling chmod commands to C.
        filemode = oct(filemode).replace("0o", "")
        try:
            os.chmod(directory, int(filemode))
        except Exception as e:
            permissions_logger.info(
                "Failed to change permissions on file or directory" +
                f" {directory} to {str(filemode)}\n")
            permissions_logger.info(e)    
    
    @staticmethod
    def symbolic_chmod(location, description):
        """chmod(location, description) --> None
        Change the access permissions of file, using a symbolic description
        of the mode, similar to the format of the shell command chmod.
        The format of description is
            * an optional letter in o, g, u, a (no letter means a)
            * an operator in +, -, =
            * a sequence of letters in r, w, x, or a single letter in o, g, u
        Example:
            chmod(myfile, "u+x")    # make the file executable for it's owner.
            chmod(myfile, "o-rwx")  # remove all permissions for all users not in the group. 
        See also the man page of chmod.
        """
        try:
            mo = Mapping.chmod_regex.match(description)
            who, op, value = mo.group("who"), mo.group("op"), mo.group("value")
            if not who:
                who = "a"
            mode = os.stat(location)[stat.ST_MODE]
            if value in ["o", "g", "u"]:
                mask = Mapping.ors((Mapping.stat_bit(who, z) for z in "rwx" if (mode & Mapping.stat_bit(value, z))))
            else:
                mask = Mapping.ors((Mapping.stat_bit(who, z) for z in value))
            if op == "=":
                mode &= ~ Mapping.ors((Mapping.stat_bit(who, z) for z in  "rwx"))
            mode = (mode & ~mask) if (op == "-") else (mode | mask)
            try:
                os.chmod(location, mode)
            except Exception as e:
                permissions_logger.error("chmod failed"+ str(location) + " mode:"+str(mode))
                permissions_logger.error(e)
        except Exception as e:
            permissions_logger.error(e)
    
    @staticmethod
    def stat_bit(who, letter):
        if who == "a":
            return Mapping.stat_bit("o", letter) | Mapping.stat_bit("g", letter) | Mapping.stat_bit("u", letter)
        return getattr(stat, "S_I%s%s" % (letter.upper(), Mapping.stat_bit_prefix[who]))
    
    @staticmethod
    def ors(sequence, initial = 0):
        return functools.reduce(operator.__or__, sequence, initial)

    @staticmethod
    @cython.boundscheck(False) # compiler directive
    @cython.wraparound(False) # compiler directive
    def run_chown_command(directory, user="", group=""):
        try:
            print("testing chown")
            os.chown(directory, int(user), int(group))
        except Exception as e:
            permissions_logger.info("chown command error")
            permissions_logger.info(e)

    @staticmethod
    def is_valid_path(input_path, mode=IS_FILE):
        """Check if the input string matches a regex and
           file mode and returns true"""
        regex = (
            r"^(?:\/|file:[\/|\\][\/|\\][\/|\\]?)?(([a-zA-Z0-9_ \-])"
            + r"\:|\\\\[a-zA-Z0-9_ -]+[\\|\/][a-zA-Z0-9_ \-]+)?([\/|\\]"
            + r"(?!CON|PRN|AUX|NUL|CONIN|CONOUT|COM|LPT)[a-zA-Z0-9_ .\-]+)+$"
        )
        permissions_logger.info(input_path)
        with suppress(Exception):
            return (
                bool(re.search(regex, input_path))
                and os.stat(input_path).st_mode & 0o170000 == mode
            )

    @staticmethod
    def change_permissions_and_ownership(
         directory, filemode, uid, gid, mode):
        permissions_logger.info("checking valid path " + directory)
        if Mapping.is_valid_path(directory, mode):
            permissions_logger.info("changing permissions and ownership")
            permissions_logger.info(directory)
            permissions_logger.info(filemode)
            permissions_logger.info(mode)
            permissions_logger.info(uid)
            permissions_logger.info(gid)
            if Mapping.run_as_non_root:
                permissions_logger.info("test")
                Mapping.run_chown_command(directory, str(os.getuid()), str(os.getgid()))
            if Mapping.g_u_bit:
                permissions_logger.info("test2")
                Mapping.symbolic_chmod(directory, "g=u")
            if filemode is not False:
                # When you just want to run g=u and not specify permissions
                Mapping.run_chmod_command(directory, filemode)
            if Mapping.ignore_user:
                uid = os.stat(directory).st_uid
            Mapping.run_chown_command(directory, str(uid), str(gid))
        else:
            permissions_logger.info("invalid file path")

    @staticmethod
    def run_g_u(directory, uid:int, gid:int, exclusions, set_uid, set_gid:int, set_sticky_bit:int, breakpoints, mode):
        try:
            permissions_logger.info("Applying g=u permissions changes to:")
            permissions_logger.info(directory)

            if Mapping.is_valid_path(directory, mode):
                bdirectory = directory.encode('utf-8') 
                permissions_logger.info(
                    "directory:" + directory + "\n" + \
                    "uid:" + str(uid) + "\n" + \
                    "gid:" + str(gid) + "\n" + \
                    "set_uid:" + str(set_uid) + "\n" + \
                    "set_gid:" + str(set_gid) + "\n" + \
                    "set_sticky_bit:" + str(set_sticky_bit) + "\n" + \
                    "breakpoints:" + "".join(str(breakpoints)) + "\n" + \
                    "exclusions:" + "".join(str(exclusions)) + "\n"
                    
                )
                change_group_permissions(
                    bdirectory, 
                    uid,
                    gid,
                    set_uid,
                    set_gid,
                    set_sticky_bit,
                    breakpoints,
                    exclusions
                )
            else:
                permissions_logger.info("invalid file path")
        except Exception as e:
            permissions_logger.error("This is a test")
            permissions_logger.error(e)


    @staticmethod
    def change_permissions_and_ownership_using_c(directory, filemode, file_extensions, uid:int, gid:int, exclusions, dirmode, breakpoints, mode):
        # Could move commands to separate script?
        permissions_logger.info("Applying permissions changes to:")
        permissions_logger.info(directory)
        try:
            if Mapping.is_valid_path(directory, mode):
                bdirectory = directory.encode('utf-8') # C requires that
                permissions_logger.info("Running recursive chmod with the following parameters")
                permissions_logger.info(
                    "directory:" + directory + "\n" + \
                    "dirmode:" + str(oct(dirmode)) + "\n" + \
                    "filemode:" + str(oct(filemode)) + "\n" + \
                    "file_extensions:" + str(file_extensions) + "\n" + \
                    "uid:" + str(uid) + "\n" + \
                    "gid:" + str(gid) + "\n" + \
                    "exclusions:" + str(exclusions) + "\n"
                )
                change_permissions(
                    bdirectory, 
                    str(oct(dirmode)).replace("0o","").encode("UTF-8"),
                    str(oct(filemode)).replace("0o","").encode("UTF-8"), 
                    file_extensions,
                    uid,
                    gid, 
                    breakpoints, 
                    exclusions
                )
            else:
                permissions_logger.info("invalid file path")
        except Exception as e:
            permissions_logger.error("This is a test")
            permissions_logger.error(e)

    @staticmethod
    def string_to_int_bool(string_var):
        if string_var.lower() == 'true':
            return 1
        return 0

    def run(self):
        self.setuid_bit = Mapping.string_to_int_bool(self.setuid_bit)
        self.setgid_bit = Mapping.string_to_int_bool(self.setgid_bit)
        self.sticky_bit = Mapping.string_to_int_bool(self.sticky_bit)
        self.breakpoint_env = self.breakpoint_env.encode('utf-8')
        if self.directory_included.lower() == 'true':
            Mapping.change_permissions_and_ownership(
                self.directory,
                self.filemode,
                self.uid,
                self.gid,
                Mapping.IS_DIR
            )
        if self.recurse_directories.lower() == 'true':
            if self.g_u_bit:
                Mapping.run_g_u(
                    self.directory,
                    self.uid,
                    self.gid,
                    self.exclude,
                    self.setuid_bit,
                    self.setgid_bit,
                    self.sticky_bit,
                    self.breakpoint_env,
                    Mapping.IS_DIR
                )
            if self.filemode:
                Mapping.change_permissions_and_ownership_using_c(
                    self.directory,
                    self.filemode,
                    self.file_extensions,
                    self.uid,
                    self.gid,
                    self.exclude,
                    self.dirmode,
                    self.breakpoint_env,
                    Mapping.IS_DIR
                )
        for item in self.include:
            fpath = self.directory + "/" + item
            if os.path.isfile(fpath):
                Mapping.change_permissions_and_ownership(
                    self.directory + "/" + item,
                    self.filemode,
                    self.uid,
                    self.gid,
                    Mapping.IS_FILE
                )
            elif os.path.isdir(fpath):
                Mapping.change_permissions_and_ownership(
                    self.directory + "/" + item,
                    self.filemode,
                    self.uid,
                    self.gid,
                    Mapping.IS_DIR
                )


    @staticmethod
    def list_tag(tag, text, parentIndex):
        b=(int(parentIndex) * (" "))
        c=((int(parentIndex)-1) * (" "))
        text = str(text)
        if text != "[]":
            text = "\n" + b + text
            return "<"+tag+">"+text.replace("]",c+"]").replace("[   ]","[]").replace("[ ]","[]")+"\n"+c+"</"+tag+">"
        else:
            return "<"+tag+">"+text+"</"+tag+">"+b+"\n"

    @staticmethod
    def tag(tag, text):
        return "<"+tag+">"+str(text)+"</"+tag+">\n"

    def __eq__(self, other):
        return (
            (self.directory == other.directory) and
            (self.filemode == other.filemode) and
            (self.uid == other.uid) and
            (self.gid == other.gid) and
            (self.directory_included == other.directory_included) and
            (self.recurse_directories == other.recurse_directories) and
            (self.include == other.include)
        )

    def __repr__(self):
        res = Mapping.tag("directory", self.directory)
        res += Mapping.tag("filemode", self.filemode)
        res += Mapping.tag("uid", self.uid)
        res += Mapping.tag("gid", self.gid)
        res += Mapping.tag("directory_included", self.directory_included)
        res += Mapping.tag("recurse_directories", self.recurse_directories)
        res += Mapping.tag("include", self.include)


def set_xml_profile_parameters(tree, selected_profile="fsmap_test"):
    try:
        permissions_logger.info("<profile>")
        profiles = tree.xpath('//profile')
        for profile in profiles:
            profile_children = profile.getchildren()
            if profile_children[0].text == selected_profile:
                permissions_logger.info(" <nfsparameters>")
                for param in profile_children[1]:
                    if param.tag is not etree.Comment:
                        permissions_logger.info(
                            "  <"+param.tag+">"+param.text+"</"+param.tag+">")
                        setattr(Mapping, param.tag, param.text)
                permissions_logger.info(" </nfsparameters>")
        permissions_logger.info("</profile>")
    except Exception as e:
        permissions_logger.info("Failed to set XML/YAML profile parameters")
        permissions_logger.info(e)

    
def apply_properties(tree):
    try:
        permissions_logger.info("Applying XML/Yaml properties to mapping")
        properties = tree.xpath('//properties')[0]
        mappings = tree.xpath('//mapping')
        for mapp in mappings:
            for item in mapp:
                if item.tag.lower() == 'dependency' or item.tag.lower() == 'file_extensions' or item.tag.lower() == 'breakpoints':
                    for include in item.getchildren()[0].getchildren():
                        for prop in properties.getchildren():
                            include.text = include.text.replace(
                                "${"+prop.tag+"}", prop.text
                            )
                else:
                    for prop in properties.getchildren():
                        permissions_logger.info(item)
                        item.text = item.text.replace("${"+prop.tag+"}", prop.text)
    except Exception as e:
        permissions_logger.info("Failed to apply XML/YAML properties")
        permissions_logger.info(e)
    return tree


def parse_file_as_tree(filepath):
    """ Parses the XML/YAML file as ElementTree. """
    try:
        permissions_logger.info("Parsing XML/Yaml file")
        permissions_logger.info(filepath)
        file_ext = Path(filepath).suffix
        if file_ext == ".xml":
            parser = etree.XMLParser(remove_blank_text=True)
            return etree.parse(filepath, parser)
        elif file_ext == ".yaml":
            yaml_file=open(filepath,"r")
            yaml_string=yaml.load(yaml_file,Loader=SafeLoader)
            xml_string=xmltodict.unparse(yaml_string)
            # Yaml doesn't natively support attributes this is to handle the few attributes we did happen to use via a workaround
            xml_string=xml_string.replace("<breakpoint><-id>", "<breakpoint id=\"")
            xml_string=xml_string.replace("</-id><-type>", "\" type=\"")
            xml_string=xml_string.replace("</-type><-with>", "\" with=\"")
            xml_string=xml_string.replace("<-with>", "\" with=\"")
            xml_string=xml_string.replace("</-type>", "\">")
            xml_string=xml_string.replace("</-with>", "\">")
            return etree.ElementTree(etree.fromstring(xml_string.encode('ascii')))
    except Exception as e:
        permissions_logger.error("Failed to parse file as tree")
        permissions_logger.error(e)
        exit(-1)

def get_string_property_as_env_preserve_case(property_name, property_value):
    try:
        return os.environ.get(
            property_name,
            property_value
        )
    except Exception as e:
        permissions_logger.error("Error getting string property as environment variable")
        permissions_logger.error(e)
        exit(-1)

def get_string_property_as_env(property_name, property_value):
    try:
        return os.environ.get(
            property_name,
            property_value
        ).lower()
    except Exception as e:
        permissions_logger.error("Error getting lowercase string property as environment variable")
        permissions_logger.error(e)
        exit(-1)

def get_property_as_env(property_name, property_value):
    try:
        return os.environ.get(
            property_name,
            property_value
        ).lower() == 'true'
    except Exception as e:
        permissions_logger.error("Error getting boolean property as environment variable")
        permissions_logger.error(e)
        exit(-1)


def get_numerical_property_as_env(property_name, property_value):
    try:
        res = os.environ.get(
            property_name,
            str(property_value)
        )
        permissions_logger.info(type(res))
        if res is not False and res.isnumeric():
            return int(res)
        else:
            return -1
    except Exception as e:
        permissions_logger.error("Error getting numerical environment variable ")
        permissions_logger.error(e)
        exit(-1)


def print_tree_structure(tree):
    try:
        pretty_printed_tree = etree.tostring(tree, pretty_print=True)
        permissions_logger.info(pretty_printed_tree.decode("UTF-8"))
    except Exception as e:
        permissions_logger.error("Failed to print XML tree structure")
        permissions_logger.error(e)

def update_from_yaml_single_item(
        k8s_client, yml_object, verbose=False, **kwargs):
    group, _, version = yml_object["apiVersion"].partition("/")
    if version == "":
        version = group
        group = "core"
    # Take care for the case e.g. api_type is "apiextensions.k8s.io"
    # Only replace the last instance
    group = "".join(group.rsplit(".k8s.io", 1))
    # convert group name from DNS subdomain format to
    # python class name convention
    group = "".join(word.capitalize() for word in group.split('.'))
    fcn_to_call = "{0}{1}Api".format(group, version.capitalize())
    k8s_api = getattr(client, fcn_to_call)(k8s_client)
    # Replace CamelCased action_type into snake_case
    kind = yml_object["kind"]
    kind = UPPER_FOLLOWED_BY_LOWER_RE.sub(r'\1_\2', kind)
    kind = LOWER_OR_NUM_FOLLOWED_BY_UPPER_RE.sub(r'\1_\2', kind).lower()
    # Expect the user to patch namespaced objects more often
    if hasattr(k8s_api, "patch_namespaced_{0}".format(kind)):
        # Decide which namespace we are going to put the object in,
        # if any
        if "namespace" in yml_object["metadata"]:
            namespace = yml_object["metadata"]["namespace"]
            kwargs['namespace'] = namespace
        if "name" in yml_object["metadata"]:
            name = yml_object["metadata"]["name"]
            kwargs['name'] = name
        resp = getattr(k8s_api, "patch_namespaced_{0}".format(kind))(
            body=yml_object, **kwargs)
    else:
        kwargs.pop('namespace', None)
        resp = getattr(k8s_api, "patch_{0}".format(kind))(
            body=yml_object, **kwargs)
    if verbose:
        msg = "{0} patched.".format(kind)
        if hasattr(resp, 'status'):
            msg += " status='{0}'".format(str(resp.status))
        permissions_logger.info(msg)
    return resp


def create_from_yaml_single_item(k8s_client, yml_object, verbose=False, **kwargs):
    group, _, version = yml_object["apiVersion"].partition("/")
    if version == "":
        version = group
        group = "core"
    # Take care for the case e.g. api_type is "apiextensions.k8s.io"
    # Only replace the last instance
    group = "".join(group.rsplit(".k8s.io", 1))
    # convert group name from DNS subdomain format to
    # python class name convention
    group = "".join(word.capitalize() for word in group.split('.'))
    fcn_to_call = "{0}{1}Api".format(group, version.capitalize())
    k8s_api = getattr(client, fcn_to_call)(k8s_client)
    # Replace CamelCased action_type into snake_case
    kind = yml_object["kind"]
    kind = UPPER_FOLLOWED_BY_LOWER_RE.sub(r'\1_\2', kind)
    kind = LOWER_OR_NUM_FOLLOWED_BY_UPPER_RE.sub(r'\1_\2', kind).lower()
    # Expect the user to create namespaced objects more often
    if hasattr(k8s_api, "create_namespaced_{0}".format(kind)):
        # Decide which namespace we are going to put the object in,
        # if any
        if "namespace" in yml_object["metadata"]:
            namespace = yml_object["metadata"]["namespace"]
            kwargs['namespace'] = namespace
        resp = getattr(k8s_api, "create_namespaced_{0}".format(kind))(
            body=yml_object, **kwargs)
    else:
        kwargs.pop('namespace', None)
        resp = getattr(k8s_api, "create_{0}".format(kind))(
            body=yml_object, **kwargs)
    if verbose:
        msg = "{0} created.".format(kind)
        if hasattr(resp, 'status'):
            msg += " status='{0}'".format(str(resp.status))
        permissions_logger.info(msg)
    return resp

def scale_on_kubernetes(idx, mapping):
    try:
        if Mapping.run_as_user:
          uid="""
          runAsUser: """+str(mapping.uid)
          gid="""
          runAsGroup: """ + str(mapping.gid)
        else:
          uid=""
          gid=""
          
        print("testing")
        print(mapping.directory)
        print(str(len(mapping.breakpoints)))
        breakpoint_directories = []
        breakpoint_env_ = ""
        if len(mapping.breakpoints) > 0:
            for breakpointe in mapping.breakpoints:
                breakpointe.init_scale_on_kubernetes(mapping, idx)
                breakpoint_directories.append(breakpointe.breakpoint_directory)
            breakpoint_env_="""
        - name: breakpoint_env
          value: \"{breakpoint_env}\"""".format(breakpoint_env=",".join(breakpoint_directories))
            
        formatted_mapping_job = Breakpointe.mapping_job.format(
            claimName = mapping.claim_name,
            directory = mapping.directory,
            namespace = mapping.namespace,
            uid = uid, gid = gid,
            mapping_index = str(idx),
            working_directory_env = "",
            replica = "",
            breakpoint_env = breakpoint_env_,
            image = mapping.image,
            cpu_request = mapping.cpu_request,
            memory_request = mapping.memory_request,
            ephemeral_storage_request = mapping.ephemeral_storage_request,
            cpu_limit = mapping.cpu_limit,
            memory_limit = mapping.memory_limit,
            ephemeral_storage_limit = mapping.ephemeral_storage_limit            
        )
        print(formatted_mapping_job)
        create_from_yaml_single_item(k8s_client, yaml.safe_load(formatted_mapping_job))
        pod = "eric-enm-permissions-mgr-" + str(idx)
        pod = urllib.parse.quote(sha256(pod.encode("UTF-8")).hexdigest())
        pods.append("/"+pod)
        
    except Exception as e:
        permissions_logger.error("Problem attempting scale_on_kubernetes")
        permissions_logger.error(e)

def update_permissions_configmap(remote_file):
    """ Saves the state of file permissions on the NFS to a configmap
        which will them be utilised in the next upgrade """
    try:
        text_file = open(remote_file, "r")
        configmap_data = text_file.read()
        text_file.close()
        permissions_mgr_configmap_secret = """apiVersion: v1
kind: Secret
metadata:
  name: eric-enm-permissions-mgr-filestore-secret
  namespace: {namespace}
type: Opaque
stringData:
  pom.yaml: |
{data}""".format(
            namespace=Mapping.namespace,
            data=textwrap.indent(configmap_data, "    ")
        )
        print(permissions_mgr_configmap_secret)
        # .replace("\n","\n      ")
        update_from_yaml_single_item(k8s_client, yaml.safe_load(permissions_mgr_configmap_secret))
        permissions_logger.info("Updated permissions filestore secret successfully")
    except Exception as e:
        permissions_logger.error("Failed to update permissions configmap successfully")
        permissions_logger.error(e)

if __name__ == "__main__":
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    config.load_kube_config("flexcenm8139.conf")
    
    allow_watch_bookmarks = True # bool | allowWatchBookmarks requests watch events with type \"BOOKMARK\". Servers that do not implement bookmarks may ignore this flag and bookmarks are sent at the server's discretion. Clients should not assume bookmarks are returned at any specific interval, nor may they assume the server will send any BOOKMARK event during a session. If this is not a watch, this field is ignored. (optional)
    _continue = '_continue_example' # str | The continue option should be set when retrieving more results from the server. Since this value is server defined, kubernetes.clients may only use the continue value from a previous query result with identical query parameters (except for the value of continue) and the server may reject a continue value it does not recognize. If the specified continue value is no longer valid whether due to expiration (generally five to fifteen minutes) or a configuration change on the server, the server will respond with a 410 ResourceExpired error together with a continue token. If the kubernetes.client needs a consistent list, it must restart their list without the continue field. Otherwise, the kubernetes.client may send another list request with the token received with the 410 error, the server will respond with a list starting from the next key, but from the latest snapshot, which is inconsistent from the previous list results - objects that are created, modified, or deleted after the first list request will be included in the response, as long as their keys are after the \"next key\".  This field is not supported when watch is true. Clients may start a watch from the last resourceVersion value returned by the server and not miss any modifications. (optional)
    field_selector = 'field_selector_example' # str | A selector to restrict the list of returned objects by their fields. Defaults to everything. (optional)
    label_selector = 'label_selector_example' # str | A selector to restrict the list of returned objects by their labels. Defaults to everything. (optional)
    limit = 56 # int | limit is a maximum number of responses to return for a list call. If more items exist, the server will set the `continue` field on the list metadata to a value that can be used with the same initial query to retrieve the next set of results. Setting a limit may return fewer than the requested amount of items (up to zero items) in the event all requested objects are filtered out and kubernetes.clients should only use the presence of the continue field to determine whether more results are available. Servers may choose not to support the limit argument and will return all of the available results. If limit is specified and the continue field is empty, kubernetes.clients may assume that no more results are available. This field is not supported if watch is true.  The server guarantees that the objects returned when using continue will be identical to issuing a single list call without a limit - that is, no objects created, modified, or deleted after the first request is issued will be included in any subsequent continued requests. This is sometimes referred to as a consistent snapshot, and ensures that a kubernetes.client that is using limit to receive smaller chunks of a very large result can ensure they see all possible objects. If objects are updated during a chunked list the version of the object that was present at the time the first list result was calculated is returned. (optional)
    pretty = 'pretty_example' # str | If 'true', then the output is pretty printed. (optional)
    resource_version = 'resource_version_example' # str | resourceVersion sets a constraint on what resource versions a request may be served from. See https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions for details.  Defaults to unset (optional)
    resource_version_match = 'resource_version_match_example' # str | resourceVersionMatch determines how resourceVersion is applied to list calls. It is highly recommended that resourceVersionMatch be set for list calls where resourceVersion is set See https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions for details.  Defaults to unset (optional)
    send_initial_events = True # bool | `sendInitialEvents=true` may be set together with `watch=true`. In that case, the watch stream will begin with synthetic events to produce the current state of objects in the collection. Once all such events have been sent, a synthetic \"Bookmark\" event  will be sent. The bookmark will report the ResourceVersion (RV) corresponding to the set of objects, and be marked with `\"k8s.io/initial-events-end\": \"true\"` annotation. Afterwards, the watch stream will proceed as usual, sending watch events corresponding to changes (subsequent to the RV) to objects watched.  When `sendInitialEvents` option is set, we require `resourceVersionMatch` option to also be set. The semantic of the watch request is as following: - `resourceVersionMatch` = NotOlderThan   is interpreted as \"data at least as new as the provided `resourceVersion`\"   and the bookmark event is send when the state is synced   to a `resourceVersion` at least as fresh as the one provided by the ListOptions.   If `resourceVersion` is unset, this is interpreted as \"consistent read\" and the   bookmark event is send when the state is synced at least to the moment   when request started being processed. - `resourceVersionMatch` set to any other value or unset   Invalid error is returned.  Defaults to true if `resourceVersion=\"\"` or `resourceVersion=\"0\"` (for backward compatibility reasons) and to false otherwise. (optional)
    timeout_seconds = 56 # int | Timeout for the list/watch call. This limits the duration of the call, regardless of any activity or inactivity. (optional)
    watch = True # bool | Watch for changes to the described resources and return them as a stream of add, update, and remove notifications. Specify resourceVersion. (optional)

        
    v1 = client.EventsV1Api()
    print("watching pod status:")
    count = 2
    while count > 1:
        count = 0
        ret = v1.list_event_for_all_namespaces(
            allow_watch_bookmarks=allow_watch_bookmarks,
            limit=limit, pretty=pretty, 
            timeout_seconds=timeout_seconds, watch=watch
        )
       
        for i in ret.items:
            permissions_logger.info(ret)
            # permissions_logger.info("%s\t%s\t%s" % (i.metadata.namespace, i.metadata.name, i.status.phase))
        time.sleep(30)
