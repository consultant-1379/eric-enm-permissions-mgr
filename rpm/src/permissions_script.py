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
import re, threading, sys, logging.handlers, os, functools, operator
import stat, requests, base64, ssl, yaml, cython
from kubernetes import client, config
from contextlib import suppress
from subprocess import Popen, PIPE
from lxml import etree
from re import sub
from pathlib import Path
from permissions_change_module.permissions_change import change_group_permissions
from permissions_change_module.permissions_change import change_permissions
from permissions_change_module.permissions_change import directory_counter
from permissions_change_module.permissions_change import file_counter
from yaml import SafeLoader
import xmltodict
from http.server import BaseHTTPRequestHandler, HTTPServer
from hashlib import sha256
from OpenSSL import crypto
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

k8s_client = None
webServer = None
metadata = ""
nodeSelectors = ""
nodeName = ""
permissions_logger = logging.getLogger('permissions_logger')
permissions_logger.setLevel(logging.INFO)
permissions_logger.addHandler(logging.StreamHandler(sys.stdout))
pods = []
termination_block = True
UPPER_FOLLOWED_BY_LOWER_RE = re.compile('(.)([A-Z][a-z]+)')
LOWER_OR_NUM_FOLLOWED_BY_UPPER_RE = re.compile('([a-z0-9])([A-Z])')
camelCase = re.compile(r'(?<!^)(?=[A-Z])')  # finds camel case names


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
    :param tags: list of tags for a logger (default is None).
    """

    def __init__(self, host, port=5025, message_type='logstash', tags=None, fqdn=False):
        super(LogstashHandler, self).__init__(host, port)
        self.formatter = LogstashFormatter(message_type, tags, fqdn)

    def makePickle(self, record):
        return self.formatter.format(record) + b'\n'


logstash_logger = logging.getLogger('logstash_logger')
logstash_logger.setLevel(logging.INFO)
logstash_logger.addHandler(logging.StreamHandler(sys.stdout))
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
    nfs_mount = "/ericsson/config_mgt"
    nfs_mount_dir = "/ericsson/config_mgt/permenv"
    working_directory_env_map = """
        - name: working_directory_env
          value: {directory_break_point}"""

    mapping_job = """
apiVersion: batch/v1
kind: Job
metadata:
  name: eric-enm-permissions-mgr-task-{claimName}{run_user}{replica}
  namespace: {namespace}
  labels:
    job: eric-enm-permissions-mgr-task
spec:
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels:
        app: eric-enm-permissions-mgr-task
    spec: {nodeSelector}
      nodeName: {nodeName}
      securityContext:
        runAsUser: {run_user}
      containers:
      - env:
        - name: run_as_non_root
          value: "true"
        - name: mapping_index
          value: "{mapping_index}"{working_directory_env}{breakpoint_env}
        name: eric-enm-permissions-mgr-task-{claimName}
        image: {image}
        command: [{conditional_command}]
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
        securityContext: {security_context}
        volumeMounts:
        - mountPath: {mount_path}
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
          claimName: {claimNameString}
      - name: eric-enm-permissions-mgr-task-secret
        secret:
          secretName: eric-enm-permissions-mgr-task-secret
      - name: eric-enm-permissions-mgr-filestore-secret
        secret:
          secretName: eric-enm-permissions-mgr-filestore-secret
      - name: eric-enm-permissions-mgr-configmap
        configMap:
          name: eric-enm-permissions-mgr-configmap
      imagePullSecrets:
      - name: {pullSecret}
      terminationGracePeriodSeconds: 300
  backoffLimit: 4"""

    def __init__(self):
        self.id = ""
        self.directories = []
        self.breakpoint_directory = ""
        self.type = ""
        self.breakpoints = []
        self.parentIndex = 0
        self.parent = ""

    def add_linked_breakpoint(self, child_breakpointe):
        self.breakpoints.append(child_breakpointe)
        child_breakpointe.parentIndex = self.parentIndex + 1
        child_breakpointe.parent = self

    def run_subcontainer(self, mapping, idx):
        permissions_logger.info("starting run_subcontainer() function")
        permissions_logger.info(idx)
        permissions_logger.info(mapping)

        security_context = """
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL"""

        if Mapping.root_squash.lower() == 'true':
            uid = str(mapping.uid)
            gid = "runAsGroup: " + str(mapping.gid)
            conditional_command = "./permissions_script_root_squash"
        else:
            uid = ""
            gid = ""
            conditional_command = "./permissions_script2"
            security_context += """
            add:
            - CHOWN"""

        if len(self.breakpoints) == 0:
            breakpoint_env_ = ""
        else:
            breakpoint_env_ = """
        - name: breakpoint_env
          value: \"{breakpoint_env}\"""".format(breakpoint_env=",".join(self.breakpoints))

        permissions_logger.info("run_subcontainer() runAsUser " + str(uid))
        permissions_logger.info("run_subcontainer() runAsGroup " + str(gid))
        permissions_logger.info("run_subcontainer() conditional_command " + str(conditional_command))
        permissions_logger.info("Security Context:\n" + security_context)

        for index, bpdirectory in enumerate(self.directories):
            replica = "-" + str(self.id) + "-" + str(uid) + "-" + str(index)
            formatted_mapping_job = Breakpointe.mapping_job.format(
                claimName=mapping.claim_name,
                claimNameString=mapping.claim_name,
                mount_path=mapping.mount_path,
                directory=mapping.directory,
                namespace=mapping.namespace,
                uid=uid,
                gid=gid,
                mapping_index=str(idx),
                working_directory_env=Breakpointe.working_directory_env_map.format(directory_break_point=bpdirectory),
                replica=replica,
                breakpoint_env=breakpoint_env_,
                image=mapping.image,
                cpu_request=mapping.cpu_request,
                memory_request=mapping.memory_request,
                ephemeral_storage_request=mapping.ephemeral_storage_request,
                cpu_limit=mapping.cpu_limit,
                memory_limit=mapping.memory_limit,
                ephemeral_storage_limit=mapping.ephemeral_storage_limit,
                nodeSelector=Mapping.nodeSelectors,
                nodeName=Mapping.nodeName,
                pullSecret=Mapping.pullSecret,
                run_user=uid,
                conditional_command=conditional_command,
                security_context=security_context
            )
            permissions_logger.info(formatted_mapping_job)
            create_from_yaml_single_item(k8s_client, yaml.safe_load(formatted_mapping_job))
            pod = f"eric-enm-permissions-mgr-task-{mapping.claim_name}{replica}"
            pod = urllib.parse.quote(sha256(pod.encode("UTF-8")).hexdigest())
            pods.append("/"+pod)
            permissions_logger.info(pods)
            permissions_logger.info("completed run_subcontainer() function")

    def init_scale_on_kubernetes(self, mapping, idx):
        permissions_logger.info("starting init_scale_on_kubernetes() function")
        permissions_logger.info(self.breakpoint_directory)
        permissions_logger.info(self.breakpoints)
        self.allow_ls_on_dir(mapping.mount_path)
        try:
            if self.type == "ls":
                for file in os.listdir(self.breakpoint_directory):
                    current_working_directory = self.breakpoint_directory + "/" + file
                    if os.path.isdir(current_working_directory):
                        self.directories.append(current_working_directory)
            elif self.type == "dir":
                self.directories.append(self.breakpoint_directory)
        except Exception as e:
            permissions_logger.info(e)

        self.run_subcontainer(mapping, idx)
        permissions_logger.info(self.directories)

        for breakpointe in self.breakpoints:
            breakpointe.scale_on_kubernetes(mapping, idx)

        permissions_logger.info("completed init_scale_on_kubernetes() function")

    def scale_on_kubernetes(self, mapping, idx):
        permissions_logger.info("starting scale_on_kubernetes() function")
        permissions_logger.info(self.breakpoint_directory)
        permissions_logger.info(self.breakpoints)

        if self.breakpoint_directory == "test":
            permissions_logger.info("running test breakpoint_directory")
        permissions_logger.info(self.parent.directories)

        try:
            for parent_directory in self.parent.directories:
                self.allow_ls_on_dir(parent_directory)
                current_working_directory = parent_directory + "/" + self.breakpoint_directory

                if os.path.isdir(current_working_directory):
                    permissions_logger.info(current_working_directory)
                    if self.type == "ls":
                        for file in os.listdir(current_working_directory):
                            permissions_logger.info(file)
                            t = os.path.join(current_working_directory, file)
                            self.directories.append(t)
                    elif self.type == "dir":
                        self.directories.append(current_working_directory)
        except Exception as e:
            permissions_logger.info("failed changing directory permissions")
            permissions_logger.info(current_working_directory)
            permissions_logger.info(e)

        for breakpointe in self.breakpoints:
            breakpointe.scale_on_kubernetes(mapping, idx)
        self.run_subcontainer(mapping, idx)
        permissions_logger.info("completed scale_on_kubernetes() function")

    def allow_ls_on_dir(self, parent_directory):
        permissions_logger.info("starting allow_ls_on_dir() function")
        try:
            Mapping.run_chmod_command_bin(parent_directory, "2775")
            x = self.breakpoint_directory.replace(parent_directory, "").split("/")
            if x[0] == "":
                x = x[1:]
            current_working_directory = parent_directory
            for directory in x:
                current_working_directory = current_working_directory + "/" + directory
                permissions_logger.info(current_working_directory)
                if os.path.isdir(current_working_directory):
                    permissions_logger.info("chown")
                    Mapping.run_chown_command_bin(current_working_directory, str(os.getuid()), str(os.getgid()))
                    try:
                        permissions_logger.info("chmod")
                        Mapping.run_chmod_command_bin(current_working_directory, "2775")
                    except Exception as e:
                        permissions_logger.info("chmod failed")
                        permissions_logger.info(e)
            permissions_logger.info("completed allow_ls_on_dir() function")
        except Exception as e:
            permissions_logger.info("Failed to allow ls on dir")
            permissions_logger.info(x)
            permissions_logger.info(current_working_directory)
            permissions_logger.info(e)

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
    pullSecret = ""

    IS_DIR = 0o040000
    IS_FILE = 0o100000

    # Ensures that the script runs as non-root
    # (Warning this does incur a performance penalty)
    run_as_non_root = "True"
    root_squash = "False"
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
    g_u_bit = "false"
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
    # The nodeName to use
    nodeName=""

    remote_file = '/var/configmaps2/pom.yaml'
    local_file = '/var/configmaps/pom.yaml'

    # The default image
    image = ""

    # default container resource usage
    cpu_request = "500m"
    memory_request = "500m"
    ephemeral_storage_request = ""

    # default container resource limits
    cpu_limit = "500m"
    memory_limit = "500m"
    ephemeral_storage_limit = ""

    stat_bit_prefix = dict(u="USR", g="GRP", o="OTH")
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
        self.ignore_user = Mapping.ignore_user
        self.create_directories = ""
        self.exclude_files = False
        self.read_write_once = False
        self.nodeName = Mapping.nodeName

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
        breakpoints_arr = []
        file_extensions = ""
        permissions_logger.info("Parsing mapping object")
        permissions_logger.info(mapping)

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
                    found = False
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
                            found = True
                        else:
                            setattr(point, att, breakpointe.attrib[att])
                    if not found:
                        breakpoints.append(point)

            elif item.tag == 'filemode' or item.tag == 'dirmode':
                permissions_logger.info("Parsing file or directory mode")
                if item.text.isnumeric():
                    setattr(self, item.tag, item.text)
                else:
                    permissions_logger.error(
                        "Non-nuermic permissions strings not supported"
                    )
                    quit()
            elif item.tag == 'file_extensions':
                permissions_logger.info("parsing file extensions")
                for extension in item.getchildren():
                    permissions_logger.info(extension)
                    for subtag in extension:
                        file_extensions = file_extensions + subtag.text + ","
                        permissions_logger.info(file_extensions)
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
                        x = x[1:]
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
                    "Failed to set the current working directory" +
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
    def run_chmod_command_bin(directory, filemode):
        permissions_logger.info("Starting run_chmod_command_bin() function")
        permissions_logger.info("run_chmod_command_bin() Directory : "+str(directory))
        permissions_logger.info("run_chmod_command_bin() Filemode : "+str(filemode))
        try:
            command = ["/usr/bin/chmod", filemode, directory]
            stdout, stderr = Popen(command, shell=False, stdout=PIPE, stderr=PIPE).communicate()
            if stderr:
                permissions_logger.info("Failed to change permissions on" + str(directory) + " to " + str(filemode))
                permissions_logger.info(stderr)
            else:
                permissions_logger.info(str(command) + " Completed succesfully in run_chmod_command_bin() function")
        except Exception as e:
            permissions_logger.info(e)

    @staticmethod
    def run_chown_command_bin(directory, user="", group=""):
        permissions_logger.info("Starting run_chown_command_bin() function")
        permissions_logger.info("run_chown_command_bin() Directory : "+str(directory))
        permissions_logger.info("run_chown_command_bin() User : "+str(user))
        permissions_logger.info("run_chown_command_bin() Group : "+str(group))
        try:
            if not group == "":
                command = [
                    "/usr/bin/chown",
                    str(user)+":"+group,
                    directory
                ]
            else:
                command = [
                    "/usr/bin/chown",
                    str(user),
                    directory
                ]
            stdout, stderr = Popen(
                command, shell=False, stdout=PIPE, stderr=PIPE
            ).communicate()
            permissions_logger.info(command)
            if stderr:
                permissions_logger.info(
                    "Failed to change chown directory " +
                    directory + " to " + str(user) + ":" + str(group))
                permissions_logger.info(stderr)
            else:
                permissions_logger.info(" ".join(command) + " completed succesfully!")
            permissions_logger.info("completed run_chown_command_bin() function")
        except Exception as e:
            permissions_logger.info(e)

    @staticmethod
    @cython.boundscheck(False)  # compiler directive
    @cython.wraparound(False)  # compiler directive
    def run_chmod_command(directory, filemode):
        permissions_logger.info("starting run_chmod_command() function")
        permissions_logger.info(directory)
        permissions_logger.info(filemode)
        # Cython supports compiling chmod commands to C.
        filemode = oct(filemode).replace("0o", "")
        try:
            os.chmod(directory, int(filemode))
            permissions_logger.info("completed run_chmod_command() function")
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
            chmod(myfile, "u+x")    # make the file executable for its owner.
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
                mode &= ~ Mapping.ors((Mapping.stat_bit(who, z) for z in "rwx"))
            mode = (mode & ~mask) if (op == "-") else (mode | mask)
            try:
                os.chmod(location, mode)
            except Exception as e:
                permissions_logger.error("chmod failed" + str(location) + " mode:"+str(mode))
                permissions_logger.error(e)
        except Exception as e:
            permissions_logger.error(e)

    @staticmethod
    def stat_bit(who, letter):
        if who == "a":
            return Mapping.stat_bit("o", letter) | Mapping.stat_bit("g", letter) | Mapping.stat_bit("u", letter)
        return getattr(stat, "S_I%s%s" % (letter.upper(), Mapping.stat_bit_prefix[who]))

    @staticmethod
    def ors(sequence, initial=0):
        return functools.reduce(operator.__or__, sequence, initial)

    @staticmethod
    @cython.boundscheck(False)  # compiler directive
    @cython.wraparound(False)  # compiler directive
    def run_chown_command(directory, user: int = 0, group: int = 0):
        try:
            permissions_logger.info("Starting run_chown_command() function")
            permissions_logger.info("run_chown_command() Directory : "+str(directory))
            permissions_logger.info("run_chown_command() User : "+str(user))
            permissions_logger.info("run_chown_command() Group : "+str(group))
            os.chown(directory, user, group)
            permissions_logger.info("Completed run_chown_command() function")
        except Exception as e:
            permissions_logger.info("Exception found in chown command. This could happened because of kubernetes "
                                    "and it is generally due to a problematic PV.")
            permissions_logger.info(directory)
            permissions_logger.info(user)
            permissions_logger.info(group)
            permissions_logger.info(e)

    @staticmethod
    def is_valid_path(input_path, mode=IS_FILE):
        permissions_logger.info("starting is_valid_path() function")
        """Check if the input string matches a regex and
           file mode and returns true"""
        regex = (
            r"^(?:\/|file:[\/|\\][\/|\\][\/|\\]?)?(([a-zA-Z0-9_ \-])"
            + r"\:|\\\\[a-zA-Z0-9_ -]+[\\|\/][a-zA-Z0-9_ \-]+)?([\/|\\]"
            + r"(?!CON|PRN|AUX|NUL|CONIN|CONOUT|COM|LPT)[a-zA-Z0-9_ .\-]+)+$"
        )
        permissions_logger.info(input_path)
        permissions_logger.info("completed is_valid_path() function")
        with suppress(Exception):
            return (
                bool(re.search(regex, input_path))
                and os.stat(input_path).st_mode & 0o170000 == mode
            )

    @staticmethod
    def change_permissions_and_ownership(directory, filemode, uid: int, gid: int):
        permissions_logger.info("starting change_permissions_and_ownership() function")
        try:
            permissions_logger.info("change_permissions_and_ownership() directory "+str(directory))
            permissions_logger.info("change_permissions_and_ownership() filemode "+str(filemode))
            permissions_logger.info("change_permissions_and_ownership() uid "+str(uid))
            permissions_logger.info("change_permissions_and_ownership() gid "+str(gid))
            Mapping.run_chown_command(directory, os.getuid(), os.getgid())
            if mapping.g_u_bit.lower() != "false":
                Mapping.symbolic_chmod(directory, "g=u")
            if filemode is not False:
                # When you just want to run g=u and not specify permissions
                Mapping.run_chmod_command(directory, filemode)
            if mapping.ignore_user.lower() != "false":
                uid = os.stat(directory).st_uid
            Mapping.run_chown_command(directory, uid, gid)
            permissions_logger.info("completed change_permissions_and_ownership() function")
        except Exception as e:
            permissions_logger.info(e)

    @staticmethod
    def change_permissions(directory, filemode):
        permissions_logger.info("starting change_permissions() function")
        try:
            permissions_logger.info("change_permissions() directory " + str(directory))
            permissions_logger.info("change_permissions() filemode " + str(filemode))
            if mapping.g_u_bit.lower() != "false":
                Mapping.symbolic_chmod(directory, "g=u")
            if filemode is not False:
                # When you just want to run g=u and not specify permissions
                Mapping.run_chmod_command(directory, filemode)
            permissions_logger.info("completed change_permissions() function")
        except Exception as e:
            permissions_logger.info(e)

    @staticmethod
    def run_g_u(directory, uid: int, gid: int, exclusions, set_uid, set_gid: int, set_sticky_bit: int,
                breakpoints, root_squash):
        try:
            permissions_logger.info("starting run_g_u() function")
            permissions_logger.info("Applying g=u permissions changes to:")
            permissions_logger.info(directory)

            bdirectory = directory.encode('utf-8') 
            permissions_logger.info(
                "directory:" + directory + "\n" +
                "uid:" + str(uid) + "\n" +
                "gid:" + str(gid) + "\n" +
                "set_uid:" + str(set_uid) + "\n" +
                "set_gid:" + str(set_gid) + "\n" +
                "set_sticky_bit:" + str(set_sticky_bit) + "\n" +
                "breakpoints:" + "".join(str(breakpoints)) + "\n" +
                "exclusions:" + "".join(str(exclusions)) + "\n" +
                "root_squash:" + "".join(str(root_squash)) + "\n"
            )
            change_group_permissions(
                bdirectory,
                uid,
                gid,
                set_uid,
                set_gid,
                set_sticky_bit,
                breakpoints,
                exclusions,
                root_squash
            )
            permissions_logger.info("completed run_g_u() function")
        except Exception as e:
            permissions_logger.error("Exception Found in run_g_u() function.")
            permissions_logger.error(e)


    @staticmethod
    def change_permissions_and_ownership_using_c(directory, filemode, file_extensions, uid:int, gid:int, exclusions, dirmode, breakpoints, exclude_files):
        # Could move commands to separate script?
        permissions_logger.info("Starting change_permissions_and_ownership_using_c() function")
        permissions_logger.info("Applying permissions changes to: "+str(directory))
        try:
            bdirectory = directory.encode('utf-8')  # C requires that
            permissions_logger.info("Running recursive chmod with the following parameters")
            permissions_logger.info(
                "directory:" + directory + "\n" + \
                "dirmode:" + str(dirmode) + "\n" + \
                "filemode:" + str(filemode) + "\n" + \
                "file_extensions:" + str(file_extensions) + "\n" + \
                "uid:" + str(uid) + "\n" + \
                "gid:" + str(gid) + "\n" + \
                "exclusions:" + str(exclusions) + "\n" + \
                "exclude_files: " + str(exclude_files) + "\n"
            )
            change_permissions(
                bdirectory, 
                str(dirmode).encode('utf-8'),
                str(filemode).encode('utf-8'), 
                file_extensions,
                uid,
                gid, 
                breakpoints, 
                exclusions,
                Mapping.environment_type.encode('utf-8'),
                str(exclude_files).encode('utf-8')
            )
            permissions_logger.info("Completed change_permissions_and_ownership_using_c() function")
        except Exception as e:
            permissions_logger.error("This is a test")
            permissions_logger.error(e)

    @staticmethod
    def string_to_int_bool(string_var):
        if string_var.lower() == 'true':
            return 1
        return 0

    def run(self):
        permissions_logger.info("starting run() function")
        self.setuid_bit = Mapping.string_to_int_bool(self.setuid_bit)
        self.setgid_bit = Mapping.string_to_int_bool(self.setgid_bit)
        self.sticky_bit = Mapping.string_to_int_bool(self.sticky_bit)
        self.breakpoint_env = self.breakpoint_env.encode('utf-8')
        self.filemode = int(self.filemode)
        permissions_logger.info("run() Directory : " + str(self.directory) + " & Filemode : "+str(self.filemode))
        permissions_logger.info("run() UID : " + str(self.uid) + " & GID : "+str(self.gid))

        if self.directory_included.lower() == 'true':
            if Mapping.root_squash.lower() == 'true':
                Mapping.change_permissions(
                    self.directory,
                    self.filemode
                )
            else:
                Mapping.change_permissions_and_ownership(
                    self.directory,
                    self.filemode,
                    int(self.uid),
                    int(self.gid)
                )
        if self.recurse_directories.lower() == 'true':
            if self.g_u_bit.lower() != 'false':
                Mapping.run_g_u(
                    self.directory,
                    int(self.uid),
                    int(self.gid),
                    self.exclude,
                    self.setuid_bit,
                    self.setgid_bit,
                    self.sticky_bit,
                    self.breakpoint_env,
                    self.root_squash
                )
            elif self.filemode:
                Mapping.change_permissions_and_ownership_using_c(
                    self.directory,
                    self.filemode,
                    self.file_extensions,
                    int(self.uid),
                    int(self.gid),
                    self.exclude,
                    self.dirmode,
                    self.breakpoint_env,
                    self.exclude_files
                )
        for item in self.include:
            if Mapping.root_squash.lower() == 'true':
                Mapping.change_permissions(
                    self.directory + "/" + item,
                    self.filemode
                )
            else:
                Mapping.change_permissions_and_ownership(
                    self.directory + "/" + item,
                    self.filemode,
                    int(self.uid),
                    int(self.gid)
                )

    @staticmethod
    def list_tag(tag, text, parentIndex):
        b = (int(parentIndex) * (" "))
        c = ((int(parentIndex)-1) * (" "))
        text = str(text)
        if text != "[]":
            text = "\n" + b + text
            return "<"+tag+">"+text.replace("]", c+"]").replace("[   ]", "[]").replace("[ ]", "[]")+"\n"+c+"</"+tag+">"
        else:
            return "<"+tag+">"+text+"</"+tag+">"+b+"\n"

    @staticmethod
    def tag(tag, text):
        return "<"+tag+">"+str(text)+"</"+tag+">\n"

    def __eq__(self, other):
        if self.gid == other.gid:
            self.update_gid = True
            return False
        return (
            (self.directory == other.directory) and
            (self.filemode == other.filemode) and
            (self.uid == other.uid) and
            (self.directory_included == other.directory_included) and
            (self.recurse_directories == other.recurse_directories) and
            (self.include == other.include)
        )

    def __repr__(self):
        permissions_logger.info("starting __repr__ function")
        res = Mapping.tag("directory", self.directory)
        res += Mapping.tag("filemode", self.filemode)
        res += Mapping.tag("uid", self.uid)
        res += Mapping.tag("gid", self.gid)
        res += Mapping.tag("directory_included", self.directory_included)
        res += Mapping.tag("recurse_directories", self.recurse_directories)
        res += Mapping.tag("include", self.include)
        permissions_logger.info("completed __repr__ function")
        return res


def set_xml_profile_parameters(tree, selected_profile="fsmap_test"):
    permissions_logger.info("starting set_xml_profile_parameters() function")
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
        permissions_logger.info("completed set_xml_profile_parameters() function")
    except Exception as e:
        permissions_logger.info("Exception Found in set_xml_profile_parameters() function")
        permissions_logger.info(e)


def apply_properties(tree):
    permissions_logger.info("Starting apply_properties() function")
    try:
        permissions_logger.info("Applying XML/Yaml properties to mapping")
        properties = tree.xpath('//properties')[0]
        mappings = tree.xpath('//mapping')
        for mapp in mappings:
            for item in mapp:
                if item.tag.lower() == 'dependency' or item.tag.lower() == 'breakpoints':
                    for include in item.getchildren()[0].getchildren():
                        for prop in properties.getchildren():
                            include.text = include.text.replace(
                                "${"+prop.tag+"}", prop.text
                            )
                elif item.tag.lower() == 'file_extensions':
                    for extension in item.getchildren():
                        permissions_logger.info(extension)
                        if extension.tag.lower() == 'file_extension':
                            for subtag in extension:
                                for prop in properties.getchildren():
                                    subtag.text = subtag.text.replace(
                                        "${"+prop.tag+"}", prop.text
                                    )
                else:
                    for prop in properties.getchildren():
                        permissions_logger.info(item.text)
                        item.text = item.text.replace("${"+prop.tag+"}", prop.text)
        permissions_logger.info("Completed apply_properties() function")
    except Exception as e:
        permissions_logger.info("Caught Exception in apply_properties() function")
        permissions_logger.info(e)
    return tree


def parse_file_as_tree(filepath):
    """ Parses the XML/YAML file as ElementTree. """
    try:
        permissions_logger.info("Starting parse_file_as_tree() function")
        permissions_logger.info(filepath)
        file_ext = Path(filepath).suffix
        if file_ext == ".xml":
            parser = etree.XMLParser(remove_blank_text=True)
            permissions_logger.info("Completed parse_file_as_tree() function for xml file_ext")
            return etree.parse(filepath, parser)
        elif file_ext == ".yaml":
            yaml_file = open(filepath, "r")
            yaml_string = yaml.load(yaml_file, Loader=SafeLoader)
            xml_string = xmltodict.unparse(yaml_string)
            # Yaml doesn't natively support attributes this is to handle the few attributes we did happen to use via a workaround
            xml_string = xml_string.replace("<breakpoint><-id>", "<breakpoint id=\"")
            xml_string = xml_string.replace("</-id><-type>", "\" type=\"")
            xml_string = xml_string.replace("</-type><-with>", "\" with=\"")
            xml_string = xml_string.replace("<-with>", "\" with=\"")
            xml_string = xml_string.replace("</-type>", "\">")
            xml_string = xml_string.replace("</-with>", "\">")
            permissions_logger.info("completed parse_file_as_tree() function for yaml file_ext")
            return etree.ElementTree(etree.fromstring(xml_string.encode('ascii')))
    except Exception as e:
        permissions_logger.error("Caught Exception in parse_file_as_tree() function")
        permissions_logger.error(e)
        exit(-1)


def get_string_property_as_env_preserve_case(property_name, property_value):
    try:
        return os.environ.get(
            property_name,
            property_value
        )
    except Exception as e:
        permissions_logger.error("Exception found while getting string property as environment variable")
        permissions_logger.error(e)
        exit(-1)


def get_string_property_as_env(property_name, property_value):
    try:
        return os.environ.get(
            property_name,
            property_value
        ).lower()
    except Exception as e:
        permissions_logger.error("Exception found while getting lowercase string property as environment variable")
        permissions_logger.error(e)
        exit(-1)


def get_property_as_env(property_name, property_value):
    try:
        return os.environ.get(
            property_name,
            property_value
        ).lower() == 'true'
    except Exception as e:
        permissions_logger.error("Exception found while getting boolean property as environment variable")
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
        permissions_logger.error("Exception found while getting numerical environment variable ")
        permissions_logger.error(e)
        exit(-1)


def print_tree_structure(tree):
    try:
        pretty_printed_tree = etree.tostring(tree, pretty_print=True)
        permissions_logger.info(pretty_printed_tree.decode("UTF-8"))
    except Exception as e:
        permissions_logger.error("Exception found in print_tree_structure() function")
        permissions_logger.error(e)


def update_from_yaml_single_item(
        k8s_client, yml_object, verbose=False, **kwargs):
    permissions_logger.info("starting update_from_yaml_single_item() function")
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
    permissions_logger.info("completed update_from_yaml_single_item() function")
    return resp


def create_from_yaml_single_item(k8s_client, yml_object, verbose=False, **kwargs):
    permissions_logger.info("starting create_from_yaml_single_item() function")
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
    permissions_logger.info("completed create_from_yaml_single_item() function")
    return resp


class CallbackHandler(BaseHTTPRequestHandler):

    watcher_stop = None
    log_props = logviewer_properties
    logger = permissions_logger
    logstash = logstash_logger
    total_number_of_files_changed = 0
    total_number_of_directories_changed = 0

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        try:
            path_split = self.path.split("_")
            pods.remove(path_split[0])            
            CallbackHandler.total_number_of_directories_changed = CallbackHandler.total_number_of_directories_changed + int(path_split[1])
            CallbackHandler.total_number_of_files_changed = CallbackHandler.total_number_of_files_changed + int(path_split[2])
        except:
            pass
            
        self.wfile.write(bytes("ok", "utf-8"))
        if len(pods) == 0:
            permissions_logger.info("Finished")
            update_permissions_configmap(Mapping.local_file)
            CallbackHandler.logstash.info("Total Number Of Files Updated = " + str(CallbackHandler.total_number_of_files_changed), CallbackHandler.log_props)
            CallbackHandler.logstash.info("Total Number Of Directories Updated = " + str(CallbackHandler.total_number_of_directories_changed), CallbackHandler.log_props)
            CallbackHandler.watcher_stop = True
            permissions_logger.info("shutting down server")
            quit()
        else:
            CallbackHandler.logger.info(pods)


def scale_on_kubernetes(idx, mapping):
    permissions_logger.info("starting scale_on_kubernetes() function")
    try:
        permissions_logger.info("scale_on_kubernetes() directory "+str(mapping.directory))
        permissions_logger.info("scale_on_kubernetes() index "+str(idx))
        permissions_logger.info("scale_on_kubernetes() breakpoint "+str(len(mapping.breakpoints)))
        breakpoint_directories = []
        if len(mapping.breakpoints) > 0:
            permissions_logger.info("scale_on_kubernetes() breakpoint active")
            for breakpointe in mapping.breakpoints:
                breakpointe.init_scale_on_kubernetes(mapping, idx)
                breakpoint_directories.append(breakpointe.breakpoint_directory)
        permissions_logger.info("completed scale_on_kubernetes() function")
        return breakpoint_directories
    except Exception as e:
        permissions_logger.error("Exception found in scale_on_kubernetes() function")
        permissions_logger.error(e)


def deploy(indexes, mapping, breakpoint_directories, uid):
    permissions_logger.info("starting deploy() function")
    permissions_logger.info("RWO - Initialize nodeName var so it only set in RWO mappings runs.")
    nodeName=""
    Mapping.nodeName=""
    # The claim_name is used in the job/pod name.
    # Making a copy of this from the configmap file value as RWO mappings
    # will need to build a unique name based on the number of replicas
    Mapping.claim_name=str(mapping.claim_name)
    if str(mapping.read_write_once).lower() != "false":
        permissions_logger.info("ReadWriteOnce Mapping found - " + str(mapping.read_write_once))
        define_image_rwo(indexes, mapping, breakpoint_directories, uid)
    else:
        create_job(indexes, mapping, breakpoint_directories, uid)


def kubernetes_cert_gen(emailAddress="ericsson@ericsson.com",
                        countryName="SE",
                        localityName="NA",
                        stateOrProvinceName="NA",
                        organizationName="Ericsson",
                        organizationUnitName="BUCI_DUAC_NAM",
                        validityStartInSeconds=0,
                        validityEndInSeconds=10*365*24*60*60):
    try:

        #####################
        #  CA Cert
        #####################
        try:
            ca_key  = crypto.PKey()
            ca_key.generate_key(crypto.TYPE_RSA, 4096)
            
            ca_cert = crypto.X509()
            ca_cert.set_version(0)
            ca_cert.set_serial_number(randint(50000000, 100000000))
            
            ca_subj = ca_cert.get_subject()
            ca_subj.C = "SE"
            ca_subj.O = "ERICSSON"
            ca_subj.OU = "BUCI_DUAC_NAM"
            ca_subj.CN = "ENM_UI_CA"

            ca_cert.add_extensions([
                crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
                crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
                crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
            ])
            
            ca_cert.gmtime_adj_notBefore(0)
            ca_cert.gmtime_adj_notAfter(validityEndInSeconds)
            ca_cert.set_issuer(ca_subj)
            ca_cert.set_pubkey(ca_key)
            ca_cert.sign(ca_key, 'sha256')

        except Exception as e:
            print("failed to create ca certificate")
            print(e)
        #####################
        #  Server Cert
        #####################

        try:
            server_key  = crypto.PKey()
            server_key.generate_key(crypto.TYPE_RSA, 4096)
            req = crypto.X509Req()
            req.set_version(0)
            serialNumber = randint(50000000, 100000000)
            subject = req.get_subject()
            subject.O = "ERICSSON"
            subject.OU = "BUCI_DUAC_NAM"
            subject.CN = "eric-enm-permissions-mgr-job"
            san_list = ["DNS:*.eric-enm-permissions-mgr-job", "DNS:eric-enm-permissions-mgr-job"]

            req.set_pubkey(server_key)
            req.sign(ca_key, "sha512")   

            server_cert = crypto.X509()
            server_cert.add_extensions([
                crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode("UTF-8")),
                crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
                crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
                crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
                crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
                crypto.X509Extension(b"keyUsage", False, b"digitalSignature, keyEncipherment, dataEncipherment"),
            ])
            server_cert.gmtime_adj_notBefore(0)
            server_cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
            server_cert.set_serial_number(serialNumber)
            server_cert.set_issuer(ca_cert.get_subject())
            server_cert.set_subject(req.get_subject())
            server_cert.set_pubkey(req.get_pubkey())
            server_cert.sign(ca_key, 'sha512') 
        except Exception as e:
            print("failed to create server certificate")
            print(e)
        print("Created ca cert successfully")
    
        try:
            permissions_mgr_certificate_secret = """apiVersion: v1
kind: Secret
metadata:
  name: eric-enm-permissions-mgr-job-secret  
  namespace: {namespace}{metadata}
type: Opaque
data:
  server.crt: {server_cert}
  server.key: {server_key}
  ca.crt: {cacrt}
            """.format(
                metadata=metadata,
                namespace=Mapping.namespace,
                server_cert=base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert)).decode("utf-8"),
                server_key=base64.b64encode(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key)).decode("utf-8"),
                cacrt=base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)).decode("utf-8")
            )
            update_from_yaml_single_item(k8s_client, yaml.safe_load(permissions_mgr_certificate_secret))
            print("Created server cert successfully")
        except Exception as e:
            print("Failed to server certificate")
            print(e)

        client_key  = crypto.PKey()
        client_key.generate_key(crypto.TYPE_RSA, 4096)
        req = crypto.X509Req()
        req.set_version(0)
        serialNumber = randint(50000000, 100000000)
        subject = req.get_subject()
        subject.commonName = "eric-enm-permissions-mgr-task"
        subject.C = "SE"
        subject.O = "ERICSSON"
        subject.OU = "BUCI_DUAC_NAM"
        subject.CN = "eric-enm-permissions-mgr-task"
        san_list = ["DNS:*.eric-enm-permissions-mgr-task", "DNS:eric-enm-permissions-mgr-task"]
        
        req.set_pubkey(client_key)
        req.sign(ca_key, "sha512")   

        client_cert = crypto.X509()
        client_cert.add_extensions([
            crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode("UTF-8")),
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
            crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth"),
            crypto.X509Extension(b"keyUsage", False, b"digitalSignature"),
        ])
        client_cert.gmtime_adj_notBefore(0)
        client_cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
        client_cert.set_serial_number(serialNumber)
        client_cert.set_issuer(ca_cert.get_subject())
        client_cert.set_subject(req.get_subject())
        client_cert.set_pubkey(req.get_pubkey())
        client_cert.sign(ca_key, 'sha512') 

        try:
            permissions_mgr_certificate_secret = """apiVersion: v1
kind: Secret
metadata:
  name: eric-enm-permissions-mgr-task-secret
  namespace: {namespace}{metadata}
type: Opaque
data:
  client.crt: {client_cert}
  client.key: {client_key}
  ca.crt: {cacrt}
            """.format(
                metadata=metadata,
                namespace=Mapping.namespace,
                client_cert=base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert)).decode("utf-8"),
                client_key=base64.b64encode(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key)).decode("utf-8"),
                cacrt=base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)).decode("utf-8")
            )
            update_from_yaml_single_item(k8s_client, yaml.safe_load(permissions_mgr_certificate_secret))
            print("Created client cert successfully")
        except Exception as e:
            print("Failed to create server certificate")
            print(e)

    except Exception as e:
        permissions_logger.error(
            "Kubernetes certificates failed to be generated. \n" + \
            "This error is usually caused due to an update of pyOpenSSL \n" + \
            "please ensure command syntax is correct for the latest version."
        )
        permissions_logger.error(e)


def update_permissions_configmap(remote_file):
    """ Saves the state of file permissions on the NFS to a configmap
        which will them be utilised in the next upgrade """
    permissions_logger.info("starting update_permissions_configmap() function")
    try:
        remote_file = Mapping.remote_file
        text_file = open(remote_file, "r")
        configmap_data = text_file.read()
        text_file.close()
        permissions_mgr_configmap_secret = """apiVersion: v1
kind: Secret
metadata:
  name: eric-enm-permissions-mgr-filestore-secret
  namespace: {namespace}{metadata}
type: Opaque
stringData:
  pom.yaml: |
{data}""".format(
            metadata=metadata,
            namespace=Mapping.namespace,
            data=textwrap.indent(configmap_data, "    ")
        )
        print(permissions_mgr_configmap_secret)
        k8s_client = client.ApiClient()
        update_from_yaml_single_item(k8s_client, yaml.safe_load(permissions_mgr_configmap_secret))
        permissions_logger.info("completed update_permissions_configmap() function")
    except Exception as e:
        permissions_logger.error("Failed to update permissions configmap successfully")
        permissions_logger.error(e)


def define_image():
    # Defines the image to be used for the job.
    permissions_logger.info("starting define_image() function")
    try:
        api = client.CoreV1Api()
        ret = api.list_namespaced_pod(Mapping.namespace)
        count = 0 
        for i in ret.items:
            if "permissions" in i.metadata.name:
                count = count + 1
                api_response = api.read_namespaced_pod(i.metadata.name, i.metadata.namespace, pretty='pretty_example')
                Mapping.image = api_response.spec.containers[0].image
                metadata = ""
                Mapping.nodeSelectors = ""
                if api_response.spec.node_selector is not None:
                    Mapping.nodeSelectors = "\n      nodeSelector:\n"
                    for label in api_response.spec.node_selector:
                        Mapping.nodeSelectors = Mapping.nodeSelectors + ("        " + label + ": " + api_response.spec.node_selector[label] + "\n")
                    print(Mapping.nodeSelectors)
                if api_response.metadata.annotations is not None:
                    metadata = metadata + "\n  annotations:\n"
                    for label in api_response.metadata.annotations:
                        metadata = metadata + ("    " + label + ":" + api_response.metadata.annotations[label] + "\n")
                    if api_response.metadata.labels is not None:
                        metadata = metadata + "  labels:\n"
                        for label in api_response.metadata.labels:
                            metadata = metadata + ("    " + label + ":" + api_response.metadata.labels[label] + "\n")
                elif api_response.metadata.labels is not None:
                    metadata = metadata + "  labels:\n"
                    for label in api_response.metadata.labels:
                        metadata = metadata + ("    " + label + ":" + api_response.metadata.labels[label] + "\n")
        permissions_logger.info("completed define_image() function")
    except Exception as e:
        permissions_logger.info("Exception found in define_image() function")
        permissions_logger.info("This uses the kubectl API please check kubelets are in working order!")
        permissions_logger.error(e)


def define_image_rwo(indexes, mapping, breakpoint_directories, uid):
    # In a RWO mapping define the mount_path, the nodeName and the claim_name
    # Store original claim_name so indexes only processed the once.
    original_claim_name=mapping.claim_name
    permissions_logger.info("starting define_image_rwo() function")
    # If multiple mount path then process them else do nothing there is only one.
    if "," in mapping.mount_path:
        idxes = mapping.mount_path.split(",")
        numberItems=len(idxes)
        count=0
        mount_path=""
        for index in idxes:
            count=count+1
            mount_path = mount_path + (index)
            if (count != numberItems):
                mount_path = mount_path + ("\n          name: mnt" + str(count) + "\n" + "        - mountPath: ")
        mapping.mount_path=str(mount_path)
    permissions_logger.info("The RWO mapping.mount_path is : " + str(mapping.mount_path))
    try:
        api = client.CoreV1Api()
        ret = api.list_namespaced_pod(Mapping.namespace)
        foundSG=False
        replicaCount=0
        for i in ret.items:
            if str(i.metadata.name).startswith(str(mapping.read_write_once)):
                foundSG=True
                Mapping.nodeName=""
                Mapping.claim_name=""
                claimNameString=""
                count = 0
                permissions_logger.info("RWO - The i.metadata.name - " + str(i.metadata.name))
                # Make the pod / clain name string unique for each replica
                mapping.claim_name=original_claim_name
                mapping.claim_name=mapping.claim_name+str(replicaCount)
                replicaCount=replicaCount+1
                permissions_logger.info("RWO - The mapping.claim_name is - " + str(mapping.claim_name))
                api_response = api.read_namespaced_pod(i.metadata.name, i.metadata.namespace, pretty='pretty_example')
                if api_response.spec.node_name is not None:
                    Mapping.nodeName = api_response.spec.node_name
                    permissions_logger.info("RWO - The node name selected is - " + str(Mapping.nodeName))
                    tempClaim=[]
                    for volume in api_response.spec.volumes:
                      if volume.persistent_volume_claim:
                         if mapping.read_write_once in volume.persistent_volume_claim.claim_name:
                            tempClaim.append(volume.persistent_volume_claim.claim_name)
                    count=0
                    last_item = tempClaim[-1]
                    for index in tempClaim:
                      count=count+1
                      claimNameString = claimNameString + (index)
                      if (index == last_item):
                         pass
                      else:
                         claimNameString = claimNameString + "\n" + "      - name: mnt" + str(count) + "\n"
                         claimNameString = claimNameString + "        persistentVolumeClaim:\n" + "          claimName: "
                    Mapping.claim_name=str(claimNameString)
                    permissions_logger.info("The RWO claimName string - " + str(Mapping.claim_name))
                create_job(indexes, mapping, breakpoint_directories, uid)
        if foundSG is False:
           permissions_logger.info("RWO - Did not find a SG named " + str(mapping.read_write_once))
           permissions_logger.info("RWO - Is the read_write_once in the configmap defined correctly")
        # Set mapping.claim_name back to original value so scale function works as expected
        mapping.claim_name=original_claim_name
        permissions_logger.info("completed define_image_rwo() function")
    except Exception as e:
        permissions_logger.info("Exception found in define_image_rwo() function")
        permissions_logger.info("This uses the kubectl API please check kubelets are in working order!")
        permissions_logger.error(e)


def create_job(indexes, mapping, breakpoint_directories, uid):
    permissions_logger.info("create_job() indexes "+str(indexes))
    permissions_logger.info(mapping.directory)
    permissions_logger.info("create_job() breakpoint_directories "+str(len(breakpoint_directories)))
    permissions_logger.info("create_job() breakpoint "+str(len(mapping.breakpoints)))

    try:
        security_context = """
                          allowPrivilegeEscalation: false
                          capabilities:
                            drop:
                            - ALL"""

        if Mapping.root_squash.lower() == 'true':
            uid = str(uid)
            gid = ""
            runAsGroup: str(mapping.gid)
            conditional_command = "./permissions_script_root_squash"
        else:
            uid = ""
            gid = ""
            conditional_command = "./permissions_script2"
            security_context += """
                            add:
                            - CHOWN"""

        breakpoint_env_ = ""

        permissions_logger.info("create_job() runAsUser " + str(uid))
        permissions_logger.info("create_job() runAsGroup " + str(gid))
        permissions_logger.info("create_job() indexes " + str(indexes))
        permissions_logger.info("create_job() conditional_command " + str(conditional_command))
        permissions_logger.info("create_job() security_context " + str(security_context))

        if len(breakpoint_directories) > 0:
            breakpoint_env_="""
        - name: breakpoint_env
          value: \"{breakpoint_env}\"""".format(breakpoint_env=",".join(breakpoint_directories))
        permissions_logger.info(breakpoint_env_)

        formatted_mapping_job = Breakpointe.mapping_job.format(
            claimName=mapping.claim_name,
            claimNameString=Mapping.claim_name,
            directory=mapping.directory,
            mount_path=mapping.mount_path,
            namespace=mapping.namespace,
            uid=uid, gid=gid,
            mapping_index=indexes,
            working_directory_env="",
            replica="",
            breakpoint_env=breakpoint_env_,
            image=mapping.image,
            cpu_request=mapping.cpu_request,
            memory_request=mapping.memory_request,
            ephemeral_storage_request=mapping.ephemeral_storage_request,
            cpu_limit=mapping.cpu_limit,
            memory_limit=mapping.memory_limit,
            ephemeral_storage_limit=mapping.ephemeral_storage_limit,
            nodeSelector=Mapping.nodeSelectors,
            nodeName=Mapping.nodeName,
            pullSecret=Mapping.pullSecret,
            run_user=uid,
            conditional_command=conditional_command,
            security_context=security_context
        )
        permissions_logger.info("create_job() formatted_mapping_job data "+str(formatted_mapping_job))
        config.load_incluster_config()
        k8s_client = client.ApiClient()
        create_from_yaml_single_item(k8s_client, yaml.safe_load(formatted_mapping_job))
        pod = f"eric-enm-permissions-mgr-task-{mapping.claim_name}"
        pod = urllib.parse.quote(sha256(pod.encode("UTF-8")).hexdigest())
        pods.append("/"+pod)
        permissions_logger.info("completed create_job() function")

    except Exception as e:
        permissions_logger.error("Exception found in create_job() function")
        permissions_logger.error(e)


def kubectl_watcher():
    # Monitors the state of pods for crashes.
    permissions_logger.info("namespace:" + Mapping.namespace)
    permissions_logger.info("watching pod status:")
    api = client.CoreV1Api()
    
    time.sleep(120)
    while CallbackHandler.watcher_stop is None:
        ret = api.list_namespaced_pod(Mapping.namespace)
        count = 0
        for i in ret.items:
            if "eric-enm-permissions-mgr-task" in i.metadata.name and ("Running" in i.status.phase or "init" in i.status.phase or "ContainerCreating" in i.status.phase):
                count = count + 1 
                permissions_logger.info("%s\t%s\t%s" % (i.metadata.namespace, i.metadata.name, i.status.phase))
                continue
            pod = urllib.parse.quote(sha256(i.metadata.name.encode("UTF-8")).hexdigest())
            if pod in pods:
                pods.remove(pod) 
        if count == 0:
            update_permissions_configmap(Mapping.local_file)
            if webServer is not None:
                try:
                    webServer.shutdown()
                except Exception as e:
                    permissions_logger.error("Failed to stop webserver")
                    permissions_logger.error(e)
            permissions_logger.info("shutting down")
            quit()
        time.sleep(60)


# The function is responsible to create directories where root is not the owner
# Refer Jira TORF-716264

def create_new_directories(mapping, directory, default_uid, default_gid):
    permissions_logger.info("Starting create_new_directories() Function ")
    permissions_logger.info("Default UID "+str(default_uid)+ " and GID "+str(default_gid))
    permissions_logger.info("Mapping UID "+str(mapping.uid)+ " and GID "+str(mapping.gid))

    permissions_logger.info("Mapping directory not available. Creating directory "+str(directory))
    command = ["/usr/bin/chown", str(os.getuid())+":"+str(os.getgid()), mapping.mount_path]
    stdout, stderr = Popen(
        command, shell=False, stdout=PIPE, stderr=PIPE
    ).communicate()
    permissions_logger.info("Completed temp permissions changes for mount path "+str(mapping.mount_path))

    permissions_logger.info("Processing directory : "+str(directory))
    try:
        command = ["/usr/bin/mkdir","-p", directory]
        stdout, stderr = Popen(
            command, shell=False, stdout=PIPE, stderr=PIPE
        ).communicate()
        if stderr :
            permissions_logger.info(f"Failed to create '{directory}' directory ")
        else:
            permissions_logger.info(f"Successfully created '{directory}' directory.")
    except OSError as e:
        permissions_logger.error(f"Error while creating directory '{directory}': {e}")

    command = ["/usr/bin/chown", str(default_uid)+":"+str(default_gid), mapping.mount_path]
    stdout, stderr = Popen(
        command, shell=False, stdout=PIPE, stderr=PIPE
    ).communicate()
    permissions_logger.info("Reverted temp permission changes of mount path "+str(mapping.mount_path))
    permissions_logger.info("Completed create_new_directories() Function ")


if __name__ == "__main__":

    try:
        Mapping.hostname = get_string_property_as_env('HOSTNAME', Mapping.hostname)
        if "KUBERNETES_SERVICE_HOST" in os.environ:
            permissions_logger.info("FOUND KUBERNETES_SERVICE_HOST in os.env" )
            # Location of the configuration pom.xml on the remote file system
            Mapping.remote_file = os.environ.get('REMOTE_FILE', '/var/configmaps2/pom.yaml')
            # Location of the configuration pom.xml on the local file system
            Mapping.local_file = os.environ.get('LOCAL_FILE', '/var/configmaps/pom.yaml')

            __init = get_property_as_env('init', "False")
            if __init:
                config.load_incluster_config()
                k8s_client = client.ApiClient()
                # The current working kubernetes namespace
                Mapping.namespace = get_string_property_as_env('namespace', Mapping.namespace)
                kubernetes_cert_gen()
                quit()

        else:
            permissions_logger.info("KUBERNETES_SERVICE_HOST not found in os.env")
            import argparse
            parser = argparse.ArgumentParser(prog='PROG')
            parser.add_argument('--local_file', nargs='?', help='local xml file must be specified', required=True)
            parser.add_argument('--remote_file', nargs='?', help='remote xml file must be specified', required=True)
            args = parser.parse_args()
            permissions_logger.info('Input file is ' + str(args.local_file))
            permissions_logger.info('Output file is ' + str(args.remote_file))
            # Location of the configuration pom.xml on the remote file system
            Mapping.remote_file = args.remote_file
            # Location of the configuration pom.xml on the local file system
            Mapping.local_file = args.local_file
            __INSTALL = get_property_as_env('INSTALL', "False")
            if __INSTALL:
                shutil.copyfile(Mapping.local_file, Mapping.remote_file)
    except Exception as e:
        permissions_logger.error("Caught Exception While Parsing Local/Remote XML files")
        permissions_logger.error(e)

    try:
        permissions_logger.info("---Parsing Local XML/YAML--- FILE")
        selected_profile = os.environ.get('PROFILE', "fsmap_test")
        left_tree = parse_file_as_tree(Mapping.local_file)
        set_xml_profile_parameters(left_tree, selected_profile)
        left_tree = apply_properties(left_tree)
    except Exception as e:
        permissions_logger.error("Caught Exception While Setting XML Profile Context")
        permissions_logger.error(e)

    try:
        permissions_logger.info("---Parsing Environment Variables---")
        for item in [ "environment_type", "complete_run", "g_u_bit", "ignore_user", "run_as_non_root", "root_squash", "sticky_bit",
                     "setgid_bit", "setuid_bit", "default_gid"]:
            setattr(Mapping, item, get_string_property_as_env(item, getattr(Mapping, item)))
        for item in ["fsmap_index", "default_dirmode", "default_filemode", "default_uid", "server_port"]:
            setattr(Mapping, item, get_numerical_property_as_env(item, getattr(Mapping, item)))
        for item in ["cpu_request", "memory_request", "ephemeral_storage_request",
                     "cpu_limit", "memory_limit", "ephemeral_storage_limit", "pullSecret"]:
            setattr(Mapping, item, get_string_property_as_env_preserve_case(item, getattr(Mapping, item)))
        permissions_logger.info("Running as " + Mapping.hostname)
    except Exception as e:
        permissions_logger.error("Failed to parse Environment Variables")
        permissions_logger.error(e)

    try:
        mapping_index = get_string_property_as_env('mapping_index', "")
        permissions_logger.info("Mapping index list "+str(mapping_index))
        permissions_logger.info("Default UID & GID "+str(Mapping.default_uid)+" & "+str(Mapping.default_gid))
        permissions_logger.info("OS UID & GID "+str(os.getuid())+" & "+str(os.getgid()))
        if mapping_index != "":
            mappings = list(left_tree.xpath('//mapping'))
            idxes = mapping_index.split(",")
            permissions_logger.info("Mapping index "+ str(idxes))
            for index in idxes:
                mapping = Mapping(mappings[int(index)])
                if mapping.create_directories != "":
                     directories_to_create = mapping.create_directories.split(",")
                     permissions_logger.info("Checking directories "+str(directories_to_create)+ " available for mount path "+str(mapping.mount_path))
                     for directory in directories_to_create:
                         s = os.stat(os.path.isdir(directory))
                         permissions_logger.info("Current process UID "+str(s.st_uid)+ " and GID "+str(s.st_gid))
                         permissions_logger.info("isDir "+str(directory)+ " Available : "+str(os.path.isdir(directory)))
                         if not os.path.exists(directory) and os.path.isdir(directory) is False:
                             permissions_logger.info("Mapping directory not available. Creating directory "+str(directory))
                             command = ["/usr/bin/chown", str(os.getuid())+":"+str(os.getgid()), mapping.mount_path]
                             stdout, stderr = Popen(
                                 command, shell=False, stdout=PIPE, stderr=PIPE
                             ).communicate()
                             permissions_logger.info("Completed temp permissions changes for mount path "+str(mapping.mount_path))
                             
                             permissions_logger.info("Processing directory : "+str(directory))
                             try:
                                 command = ["/usr/bin/mkdir","-p", directory]
                                 stdout, stderr = Popen(
                                     command, shell=False, stdout=PIPE, stderr=PIPE
                                 ).communicate()
                                 if stderr :
                                     permissions_logger.info(f"Failed to create '{directory}' directory ")
                                 else:
                                    permissions_logger.info(f"Successfully created '{directory}' directory.")
                             except OSError as e:
                                 permissions_logger.error(f"Error while creating directory '{directory}': {e}")
 
                             command = ["/usr/bin/chown", str(Mapping.default_uid)+":"+str(Mapping.default_gid), mapping.mount_path]
                             stdout, stderr = Popen(
                                 command, shell=False, stdout=PIPE, stderr=PIPE
                             ).communicate()
                             permissions_logger.info("Reverted temp permission changes of mount path "+str(mapping.mount_path))
                mapping.run()
            pod = Mapping.hostname
            pod = urllib.parse.quote(sha256(pod.encode("UTF-8")).hexdigest())
            permissions_logger.info("Number of directories changed " + str(directory_counter()))
            permissions_logger.info("Number of files changed " + str(file_counter()))
            server_url = f"https://eric-enm-permissions-mgr-job:{str(Mapping.server_port)}/{pod}"
            server_url = server_url + "_" + str(directory_counter())
            server_url = server_url + "_" + str(file_counter())
            cert_file_path = "/var/secrets/client.crt"
            key_file_path = "/var/secrets/client.key"
            ca_file_path = "/var/secrets/ca.crt"

            x = ""
            count = 0
            while x != "ok" and count < 5:
                try:
                    permissions_logger.info(x)
                    time.sleep(randint(1,5))
                    x = requests.get(server_url, cert=(cert_file_path, key_file_path), verify=ca_file_path)
                    permissions_logger.info(x)
                    x=x.text
                except Exception as e:
                    permissions_logger.error("Failed to get response from server")
                    permissions_logger.error(e)
                    count = count + 1
            logstash_logger.info("Total Number Of Files Updated = " + str(directory_counter()), logviewer_properties)
            logstash_logger.info("Total Number Of Directories Updated = " + str(file_counter()), logviewer_properties)
            quit()
                
        else:
            uids_for_claim_name = []
            claim_uid_map = {}

            if "KUBERNETES_SERVICE_HOST" in os.environ:
                config.load_incluster_config()
                define_image()
            if "fsmap_index" in os.environ:
                mappings = [Mapping(x) for x in list(left_tree.xpath('//fsmaps/fsmap['+str(Mapping.fsmap_index)+']//mapping'))]
            else:
                mappings = [Mapping(x) for x in list(left_tree.xpath('//mapping'))]

            if "KUBERNETES_SERVICE_HOST" in os.environ:
                config.load_incluster_config()
                define_image()

                for mapping in mappings:
                    try:
                        uid_values = str(mapping.uid).split(",")
                        if mapping.claim_name in claim_uid_map:
                          # If the claim_name exists, merge the new uid_values with the existing ones
                          claim_uid_map[mapping.claim_name].extend(uid_values)
                        else:
                          claim_uid_map[mapping.claim_name] = uid_values
                        print("Current claim_uid_map:", claim_uid_map)
                        if mapping.create_directories != "":
                            directories_to_create = mapping.create_directories.split(",")
                            permissions_logger.info("Current Mount Path : "+str(mapping.mount_path)+" directories to create : "+str(directories_to_create))
                            for directory in directories_to_create:
                                permissions_logger.info("Checking is dir "+str(directory)+ " Available : "+str(os.path.isdir(directory)))
                                if not os.path.exists(directory) and os.path.isdir(directory) is False:
                                    create_new_directories(mapping, directory, Mapping.default_uid, Mapping.default_gid)

                            for directory in directories_to_create:
                                permissions_logger.info("Updating CHMOD & CHOWN for created directories")
                                command = ["/usr/bin/chmod",mapping.dirmode,directory]
                                stdout, stderr = Popen(
                                    command, shell=False, stdout=PIPE, stderr=PIPE
                                ).communicate()

                                command = ["/usr/bin/chown", str(mapping.uid)+":"+str(mapping.gid), directory]
                                stdout, stderr = Popen(
                                    command, shell=False, stdout=PIPE, stderr=PIPE
                                ).communicate()
                                permissions_logger.info("Updated CHMOD & CHOWN for created directories")

                    except Exception as e:
                        permissions_logger.info(e)

                __INSTALL = get_property_as_env('INSTALL', "False")
                if __INSTALL:
                    config.load_incluster_config()
                    update_permissions_configmap(Mapping.local_file)
                    quit()
                    # shutil.copyfile(local_file, Mapping.remote_file)
            
            if not Mapping.complete_run == "True" and os.path.isfile(Mapping.remote_file):
                permissions_logger.info("---Parsing Remote XML/YAML--- FILE")
                right_tree = apply_properties(parse_file_as_tree(Mapping.remote_file))
                root_squash_remote = get_string_property_as_env("root_squash", getattr(Mapping, "root_squash"))
                if root_squash_remote.lower() == 'true':
                    permissions_logger.info("root_squash_remote")
                else:
                    permissions_logger.info("no_squash_remote")
                if "fsmap_index" in os.environ:
                    mappings2 = [Mapping(x) for x in list(right_tree.xpath('//fsmaps/fsmap['+str(Mapping.fsmap_index)+']//mapping'))]
                else:
                    mappings2 = [Mapping(x) for x in list(right_tree.xpath('//mapping'))]
                if "KUBERNETES_SERVICE_HOST" in os.environ:
                    try:
                        for mapping in mappings:
                            permissions_logger.info(mapping)
                        k8s_client = client.ApiClient()
                        # Verifying the job executes correctly on kubernetes
                        claim_names = []
                        idxes = []
                        bdirectories = []
                        last_index = 0
                        lastmapping = None
                        
                        mapping_dict = {}
                        for index, mapping in enumerate(mappings):
                            if len(mapping.breakpoints) > 0:
                                permissions_logger.info("Skipping indexing due to breakpoints %s", str(index))
                                continue
                            if not mapping_dict.get(mapping.claim_name):
                                mapping_dict[mapping.claim_name] = str(index)
                            else:
                                index = mapping_dict.get(mapping.claim_name) + "," + str(index)
                                mapping_dict[mapping.claim_name] = index
                        permissions_logger.info("created mapping_dict ")
                        permissions_logger.info(mapping_dict)
                        
                        for idx, mapping in enumerate(mappings):
                            permissions_logger.info("starting mapping processing")
                            permissions_logger.info("processed claim_names "+str(claim_names))
                            permissions_logger.info("current claim_name "+str(mapping.claim_name))
                            permissions_logger.info("index of current claim name " + str(mapping_dict.get(mapping.claim_name)))
                            bdirectories.append([])                            
                            mapping_index = mapping_dict.get(mapping.claim_name)
                            breakpoint_dirs = scale_on_kubernetes(idx, mapping)
                            for breakpoint_dir in breakpoint_dirs:
                                bdirectories[last_index - 1].append(breakpoint_dir)
                            if mapping.claim_name not in claim_names:
                                permissions_logger.info("mapping.claim_name not in claim_names")
                                if mapping.root_squash.lower() == 'true':
                                    permissions_logger.info("mapping.root_squash")
                                    unique_uids_list = list(set(claim_uid_map[mapping.claim_name]))
                                    print("Current unique_uids_list:", unique_uids_list)
                                    for uid in unique_uids_list:
                                        deploy(mapping_index, mapping, bdirectories[last_index - 1], uid)
                                else:
                                    permissions_logger.info("mapping.root_squash else")
                                    uid = claim_uid_map[mapping.claim_name][0]
                                    deploy(mapping_index, mapping, bdirectories[last_index - 1], uid)
                                claim_names.append(mapping.claim_name)
                            else:
                                permissions_logger.info("skipping the mapping as its already processed as group "+str(mapping))
                                continue
                            permissions_logger.info("completed mapping processing")

                        # The code aims to handle individual claim names by associating them with their respective indices, 
                        # where these indices play a crucial role in subsequent grouped operations. 
                        # The implementation has undergone refactoring, resulting in two distinct blocks. 
                        # The initial block constructs a dictionary that maps claim names to their corresponding indices. 
                        # The subsequent block leverages this dictionary to efficiently process claims in alignment with their mapping.
                        # Keeping the below code for reference. This needs to be get remove after 2-3 cycle of delivery-testing

                        # for idx, mapping in enumerate(mappings):
                        #     permissions_logger.info("current mapping "+mapping)
                        #     if mapping.claim_name in claim_names:
                        #         # idxes[last_index - 1] = idxes[last_index - 1]  + "," + str(idx)
                        #         breakpoint_dirs = scale_on_kubernetes(idx, mapping)
                        #         for breakpoint_dir in breakpoint_dirs:
                        #             bdirectories[last_index - 1].append(breakpoint_dir)
                        #     elif mapping.claim_name not in claim_names:
                        #         if last_index != 0:
                        #             deploy(idxes[last_index-1], lastmapping, bdirectories[last_index-1])
                        #         claim_names.append(mapping.claim_name)
                        #         idxes.append(str(idx))
                        #         bdirectories.append([])
                        #         last_index = last_index + 1
                        #         breakpoint_dirs = scale_on_kubernetes(idx, mapping)
                        #         for breakpoint_dir in breakpoint_dirs:
                        #             bdirectories[last_index - 1].append(breakpoint_dir)
                        #         lastmapping = mapping
                        # permissions_logger.info("PM-11 FLAG")
                        # if last_index != 0:
                            # permissions_logger.info("PM-12 FLAG Going to call Deploy Function At Last")
                            # permissions_logger.info(bdirectories[last_index-1])
                            # permissions_logger.info(idxes[last_index-1])
                            # permissions_logger.info(lastmapping)
                            # permissions_logger.info(mapping_dict.get(mapping.claim_name))               
                            # deploy(mapping_dict.get(mapping.claim_name), lastmapping, bdirectories[last_index-1])
                        termination_block = False
                        webServer = HTTPServer((Mapping.hostname, Mapping.server_port), CallbackHandler)
                        loop = True
                        watcher = threading.Thread(target=kubectl_watcher)
                        watcher.start()
                        while loop:
                            try:
                                webServer.socket = ssl.wrap_socket(webServer.socket,
                                                                   keyfile="/var/secrets/server.key",
                                                                   certfile='/var/secrets/server.crt',
                                                                   server_side=True,
                                                                   cert_reqs=ssl.CERT_REQUIRED,
                                                                   ssl_version=ssl.PROTOCOL_TLS,
                                                                   ca_certs='/var/secrets/ca.crt',
                                                                   do_handshake_on_connect=True,
                                                                   suppress_ragged_eofs=True,
                                                                   ciphers='')
                                permissions_logger.info("test")
                                loop = False
                            except Exception as e:
                                loop = True
                        try:
                            permissions_logger.info("Server started https://%s:%s" % (Mapping.hostname, Mapping.server_port))
                            webServer.serve_forever()
                        except Exception as e:
                            permissions_logger.error(e)
                            pass
                        webServer.server_close()
                        permissions_logger.info("Server stopped.")
                    except Exception as e:
                      traceback.print_exc()
                      permissions_logger.error("Found exception in reading the logs")
                      permissions_logger.error(e)

                else:
                    try:
                        for idx, mapping in enumerate(mappings):
                            if mapping not in mappings2:
                                permissions_logger.info(mapping)
                                permissions_logger.info(mapping.namespace)
                                threading.Thread(mapping.run())
                    except Exception as e:
                        permissions_logger.info('Found exception3 in reading the logs')
                        permissions_logger.error(e)
            else:
                if "KUBERNETES_SERVICE_HOST" in os.environ:
                    try:
                        config.load_incluster_config()
                        k8s_client = client.ApiClient()
                        # Verifying the job executes correctly on kubernetes
                        claim_names = []
                        idxes = []
                        bdirectories = []
                        last_index = 0
                        lastmapping = None
                        for idx, mapping in enumerate(mappings):
                            permissions_logger.info(mapping)
                            if mapping.claim_name in claim_names:
                                idxes[last_index - 1] = idxes[last_index - 1] + "," + str(idx)
                                breakpoint_dirs = scale_on_kubernetes(idx, mapping)
                                for breakpoint_dir in breakpoint_dirs:
                                    bdirectories[last_index - 1].append(breakpoint_dir)
                            elif mapping.claim_name not in claim_names:
                                if last_index != 0:
                                    if mapping.root_squash.lower() == 'true':
                                        permissions_logger.info("root_squash enabled")
                                        unique_uids_list = list(set(claim_uid_map[mapping.claim_name]))
                                        for uid in unique_uids_list:
                                            deploy(idxes[last_index-1], lastmapping, breakpoint_dirs[last_index], uid)
                                    else:
                                        uid = claim_uid_map[mapping.claim_name][0]
                                        deploy(idxes[last_index - 1], lastmapping, breakpoint_dirs[last_index], uid)
                                claim_names.append(mapping.claim_name)
                                idxes.append(str(idx))
                                bdirectories.append([])
                                last_index = last_index + 1
                                breakpoint_dirs = scale_on_kubernetes(idx, mapping)
                                for breakpoint_dir in breakpoint_dirs:
                                    bdirectories[last_index - 1].append(breakpoint_dir)
                                lastmapping = mapping
                        if last_index != 0:
                            if mapping.root_squash.lower() == 'true':
                                unique_uids_list = list(set(claim_uid_map[mapping.claim_name]))
                                for uid in unique_uids_list:
                                    deploy(idxes[last_index-1], lastmapping, bdirectories[last_index-1], uid)
                            else:
                                uid = claim_uid_map[mapping.claim_name][0]
                                deploy(idxes[last_index - 1], lastmapping, bdirectories[last_index - 1], uid)
                        webServer = HTTPServer((Mapping.hostname, Mapping.server_port), CallbackHandler)
                        permissions_logger.info("Server started http://%s:%s" % (Mapping.hostname, Mapping.server_port))
                        api = client.CoreV1Api()
                        loop = True
                        watcher = threading.Thread(target=kubectl_watcher)
                        watcher.start()
                        while loop:
                            permissions_logger.info("--Waiting for kubernetes to make cert secret available--")
                            try:
                                webServer.socket = ssl.wrap_socket(webServer.socket,
                                                                   keyfile="/var/secrets/server.key",
                                                                   certfile='/var/secrets/server.crt',
                                                                   server_side=True,
                                                                   cert_reqs=ssl.CERT_REQUIRED,
                                                                   ssl_version=ssl.PROTOCOL_TLS,
                                                                   ca_certs='/var/secrets/ca.crt',
                                                                   do_handshake_on_connect=True,
                                                                   suppress_ragged_eofs=True,
                                                                   ciphers=''
                                                                   )
                                permissions_logger.info("test")
                                loop = False
                            except Exception as e:
                                loop = True
                        try:
                            webServer.serve_forever()
                        except Exception as e:
                            permissions_logger.error(e)
                            pass
                        webServer.server_close()
                        permissions_logger.info("Server stopped.")
                    except Exception as e:
                        permissions_logger.info(e)
                else:
                    for idx, mapping in enumerate(mappings):
                        permissions_logger.info(mapping)
                        mapping.run()
            # shutil.copyfile(local_file, remote_file)
    except Exception as e:
        permissions_logger.error("Caught exception while processing chown/chmod command")
        permissions_logger.error(e)        
        quit()
