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
camelCase=compile(r'(?<!^)(?=[A-Z])') # finds camel case names

permissions_logger = logging.getLogger('permissions_logger')
permissions_logger.setLevel(logging.INFO)
permissions_logger.addHandler(logging.StreamHandler(sys.stdout))
pods = []
UPPER_FOLLOWED_BY_LOWER_RE = compile('(.)([A-Z][a-z]+)')
LOWER_OR_NUM_FOLLOWED_BY_UPPER_RE = compile('([a-z0-9])([A-Z])')
envfiles = []

class Breakpointe:

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
          value: "{mapping_index}"{working_directory_env}{exclude_subdirectories_env}
        name: eric-enm-permissions-mgr-task-{claimName}
        image: armdocker.rnd.ericsson.se/proj_oss_releases/eric-enm-permissions-mgr:inapp_test8
        imagePullPolicy: Always
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
      - name: permissions-mgr-task-secret
        secret:
          secretName: permissions-mgr-task-secret
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
        self.excluded_subdirectories=[]
        self.parentIndex=0
        self.parent=""

    def add_linked_breakpoint(self, child_breakpointe):
        self.breakpoints.append(child_breakpointe)
        child_breakpointe.parentIndex = self.parentIndex + 1
        child_breakpointe.parent = self

    def scale_on_kubernetes(self, mapping, idx):
        dirs = []
        print("testing==")
        print(self.breakpoint_directory)
        print(self.breakpoints)
        if self.parent == "":
            self.allow_ls_on_dir("")
            print("test123")
            for file in os.listdir(self.breakpoint_directory):
                current_working_directory = self.breakpoint_directory + "/" + file
                if os.path.isdir(current_working_directory):
                    self.directories.append(current_working_directory)
            print(self.directories)
            for breakpointe in self.breakpoints:
                breakpointe.scale_on_kubernetes(mapping, idx)
        else:
            print("test467")
            if self.breakpoint_directory== "test":
                print("foobar")

            for parent_directory in self.parent.directories:
                self.allow_ls_on_dir(parent_directory)
                current_working_directory = parent_directory + "/" + self.breakpoint_directory
                
                if os.path.isdir(current_working_directory):
                    print(current_working_directory)
                    if self.type == "ls":
                        for file in os.listdir(current_working_directory):
                            print(file)
                            t = os.path.join(current_working_directory, file)
                            self.parent.excluded_subdirectories.append(t)
                            self.directories.append(t)
                    elif self.type == "dir":
                        self.parent.excluded_subdirectories.append(current_working_directory)
                        self.directories.append(current_working_directory)
           
            for breakpointe in self.breakpoints:
                breakpointe.scale_on_kubernetes(mapping, idx)
        
        if mapping.run_as_user:
            uid="""
          runAsUser: """+str(mapping.uid)
            gid="""
          runAsGroup: """ + str(mapping.gid)
        else:
            uid=""
            gid=""

        working_directory_env_map="""
        - name: working_directory_env
          value: {directory_break_point}"""

        if len(self.excluded_subdirectories) == 0:
            exclude_subdirectories_env_ = ""
        else:
            envfiles.append( '/ericsson/config_mgt/'+str(self.id)+".env")
            env_file = '/ericsson/config_mgt/'+str(self.id)+".env"
            os.chown("/ericsson/config_mgt", os.getuid(), os.getgid())
            st = os.stat("/ericsson/config_mgt")
            os.chmod("/ericsson/config_mgt", st.st_mode | stat.S_IXGRP | stat.S_IWGRP)
            with open(env_file, 'w') as filehandle:
                filehandle.write(",".join(self.excluded_subdirectories))
            exclude_subdirectories_env_="""
        - name: exclude_subdirectories_env
          value: \"{exclude_subdirectories_env}\"""".format(exclude_subdirectories_env=env_file)

        for index, bpdirectory in enumerate(self.directories):
            formatted_mapping_job = Breakpointe.mapping_job.format(
                claimName=mapping.claim_name, 
                directory=mapping.directory,
                namespace=mapping.namespace,
                uid=uid,
                gid=gid,
                mapping_index=str(idx),
                working_directory_env=working_directory_env_map.format(directory_break_point=bpdirectory),
                replica="-"+str(self.id)+"-"+str(index),
                exclude_subdirectories_env=exclude_subdirectories_env_
            )
            print(formatted_mapping_job)
            # create_from_yaml_single_item(k8s_client, yaml.safe_load(formatted_mapping_job))
            pod = "eric-enm-permissions-mgr-" + str(idx) + "-" + str(bpdirectory)
            pod = urllib.parse.quote(sha256(pod.encode("UTF-8")).hexdigest())
            pods.append("/"+pod)
            print(pods)

    def allow_ls_on_dir(self, parent_directory):
        x = self.breakpoint_directory.split("/")
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
        res += tab + Mapping.tag("excluded_subdirectories", self.excluded_subdirectories)
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

    chmod_regex = compile(r"(?P<who>[uoga]?)(?P<op>[+\-=])(?P<value>[ugo]|[rwx]*)")
    stat_bit_prefix = dict(u = "USR", g = "GRP", o = "OTH")

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

        included = []
        excluded = []
        breakpoints = []
        breakpoints_arr =[]
        file_extensions = ""
        for item in mapping:
            item.tag = sub(camelCase, '_', item.tag).lower()
            if item.tag == 'dependency':
                for included_excluded in item.getchildren()[0].getchildren():
                    if included_excluded.tag.lower() == "include":
                        included.append(included_excluded.text)
                    elif included_excluded.tag.lower() == "exclude":
                        excluded.append(included_excluded.text)
            elif item.tag == 'breakpoints':
                print("testing2")
                print(item.getchildren()[0])
                print(item.getchildren()[0].text)
                for breakpointe in item.getchildren():
                    print(breakpointe.text)
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
                print(breakpoints)
            elif item.tag == 'filemode' or item.tag == 'dirmode':
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
                for file_extension in item.getchildren()[0].getchildren():
                    file_extensions = file_extensions + file_extension.text + ","
            else:
                print(item.tag)
                print(item.text)
                if item.text.isnumeric():
                    setattr(self, item.tag, int(item.text))
                else:
                    setattr(self, item.tag, item.text)
        self.include = included
        self.breakpoints = breakpoints 
        if "working_directory_env" in os.environ:
            try:
                directory = get_string_property_as_env('working_directory_env', self.directory)
                if is_valid_path(directory, IS_DIR):
                    print(f"Setting Working directory: {directory}")
                    self.directory = directory
                else:
                    raise ValueError("Failed to access working directory")
            except Exception as e:
                print("Failed to set the current working directory please ensure that the directory is correctly mounted and the directory has not been deleted.")
                print(e)
        if "exclude_subdirectories_env" in os.environ:
            try:
                exclude_subdirectories_env = get_string_property_as_env('exclude_subdirectories_env', '')
                print(f"Setting excluded subdirectories: {exclude_subdirectories_env}")
                exclude_subdirectories_env = exclude_subdirectories_env.split(",")
                if len(exclude_subdirectories_env > 0):
                    for exclude in exclude_subdirectories_env:
                        excluded.append(exclude)
                self.directory = directory
            except Exception as e:
                print("Failed to exclude subdirectories environment variable")
                print(e)
        
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
            if group is not "" and user is not "":
                os.chown(directory, int(user), int(group))
            elif user is not "":
                os.chown(directory, int(user))
            elif group is not "":
                os.chown(directory, int(group))
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
                bool(search(regex, input_path))
                and os.stat(input_path).st_mode & 0o170000 == mode
            )

    @staticmethod
    def escape_ansi_colors(string_array):
        """ Regex to escape ansi colors.
            NOTE: Regex MUST be used here as Python's .replace and .split functions won't replace them.
            :param string_array: The string array containing ansi colors.
            :return: The string array without ansi colors """
        for idx, value in enumerate(string_array):
            string_array[idx] = sub(r'(\x1b|\\e)\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', '', value)
        return string_array

    @staticmethod
    def change_permissions_and_ownership(
         directory, filemode, uid, gid, mode):
        permissions_logger.info("checking valid path " + directory)
        if Mapping.is_valid_path(directory, mode):
            permissions_logger.info("valid file path")
            permissions_logger.info(directory)
            permissions_logger.info(filemode)
            permissions_logger.info(mode)
            if Mapping.run_as_non_root:
                permissions_logger.info("test")
                Mapping.run_chown_command(directory, os.getuid(), os.getgid())
            if Mapping.g_u_bit:
                permissions_logger.info("test2")
                Mapping.symbolic_chmod(directory, "g=u")
            if filemode is not False:
                # When you just want to run g=u and not specify permissions
                Mapping.run_chmod_command(directory, filemode)
            if Mapping.ignore_user:
                uid = ""
            Mapping.run_chown_command(directory, uid, gid)
        else:
            permissions_logger.info("invalid file path")


    @staticmethod
    def change_permissions_and_ownership_using_c(directory, filemode, file_extensions, uid:int, gid:int, exclusions, dirmode, mode,  step = 100, threads=100):
        # Could move commands to separate script?
    
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
                    exclusions
                )
            else:
                permissions_logger.info("invalid file path")
        except Exception as e:
            permissions_logger.error("This is a test")
            permissions_logger.error(e)



    @staticmethod
    def run_g_u(directory, uid:int, gid:int, exclusions, mode, step = 100, threads=100):
        permissions_logger.info(directory)
        try:
            if Mapping.is_valid_path(directory, mode):
                bdirectory = directory.encode('utf-8') 
                permissions_logger.info(
                    "directory:" + directory + "\n" + \
                    "uid:" + str(uid) + "\n" + \
                    "gid:" + str(gid) + "\n" + \
                    "exclusions:" + str("".join(exclusions)) + "\n"
                )
                change_group_permissions(bdirectory, uid, gid, exclusions)
             
            else:
                permissions_logger.info("invalid file path")
        except Exception as e:
            permissions_logger.error("This is a test")
            permissions_logger.error(e)

    def run(self):
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
        return res


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
    try:
        file_ext = Path(filepath).suffix
        if file_ext == ".xml":
            parser = etree.XMLParser(remove_blank_text=True)
            return etree.parse(filepath, parser)
        elif file_ext == ".yaml":
            yaml_file=open(filepath,"r")
            yaml_string=yaml.load(yaml_file,Loader=SafeLoader)
            xml_string=xmltodict.unparse(yaml_string)
            return etree.ElementTree(etree.fromstring(xml_string.encode('ascii')))
    except Exception as e:
        permissions_logger.error(e)
        exit(-1)

def get_string_property_as_env(property_name, property_value):
    try:
        return os.environ.get(
            property_name,
            property_value
        ).lower()
    except Exception as e:
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


def create_from_yaml_single_item(
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


class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        try:
            pods.remove(self.path)
            permissions_logger.info(pods)
        except Exception as e:
            permissions_logger.error(e)
            permissions_logger.info(pods)
        self.wfile.write(bytes("ok", "utf-8"))
        if len(pods) == 0:
            permissions_logger.info("Finished")
            time.sleep(300)
            exit()


def allow_ls_on_dir(ptr, directory, i, xlen, uid, gid):
    directory = directory + "/" + ptr[i]
    os.chown(directory, os.getuid(), os.getgid())
    st = os.stat(directory)
    os.chmod(directory, st.st_mode | stat.S_IXGRP)
    print("test1")
    print(directory)
    if i < xlen - 1:
        allow_ls_on_dir(ptr, directory, i+1, xlen, uid, gid)
    print("test2")
    print(directory)
    os.chown(directory, uid, gid)


def scale_on_kubernetes(idx, mapping):
    try:
        if mapping.run_as_user:
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
        if len(mapping.breakpoints) > 0:
        #breakpoint is a reserved name in python
            working_directory_env_map="""
        - name: working_directory_env
          value: {directory_break_point}"""

            excluding = ""
            for breakpointe in mapping.breakpoints:
                breakpointe.scale_on_kubernetes(mapping, idx)
                excluding += ",".join(breakpointe.directories)

            excluded_subdirectories="""
        - name: exclude_subdirectories_env
          value: \"{exclude_subdirectories_env}\"""".format(exclude_subdirectories_env=excluding)
            formatted_mapping_job = Breakpointe.mapping_job.format(
                claimName=mapping.claim_name, 
                directory=mapping.directory,
                namespace=mapping.namespace,
                uid=uid, gid=gid,
                mapping_index=str(idx),
                working_directory_env="",
                replica="",
                exclude_subdirectories_env=excluded_subdirectories
            )
            print(formatted_mapping_job)
            # create_from_yaml_single_item(k8s_client, yaml.safe_load(formatted_mapping_job))
            pod = "eric-enm-permissions-mgr-" + str(idx)
            pod = urllib.parse.quote(sha256(pod.encode("UTF-8")).hexdigest())
            pods.append("/"+pod)
        else:
            formatted_mapping_job = Breakpointe.mapping_job.format(
                claimName=mapping.claim_name, 
                directory=mapping.directory,
                namespace=mapping.namespace,
                uid=uid, gid=gid,
                mapping_index=str(idx),
                working_directory_env="",
                replica="",
                exclude_subdirectories_env=""
            )
            # create_from_yaml_single_item(k8s_client, yaml.safe_load(formatted_mapping_job))
            print(formatted_mapping_job)
            pod = "eric-enm-permissions-mgr-" + str(idx)
            pod = urllib.parse.quote(sha256(pod.encode("UTF-8")).hexdigest())
            pods.append("/"+pod)
        
    except Exception as e:
        permissions_logger.error("Problem attempting scale_on_kubernetes")
        permissions_logger.error(e)



def kubernetes_cert_gen(
    emailAddress="ericsson@ericsson.com",
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
        ca_key  = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, 4096)
        
        ca_cert = crypto.X509()
        ca_cert.set_version(2)
        ca_cert.set_serial_number(randint(50000000,100000000))
        
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

        #####################
        #  Server Cert
        #####################

        server_key  = crypto.PKey()
        server_key.generate_key(crypto.TYPE_RSA, 4096)
        req = crypto.X509Req()
        req.set_version(2)
        serialNumber = randint(50000000,100000000)
        subject = req.get_subject()
        subject.commonName = "eric-enm-permissions-mgr-job"
        ca_subj.C = "SE"
        ca_subj.O = "ERICSSON"
        ca_subj.OU = "BUCI_DUAC_NAM"
        ca_subj.CN = "ENM_UI_CA"
        subject.CN = "eric-enm-permissions-mgr-job"
        san_list = ["DNS:*.eric-enm-permissions-mgr-job", "DNS:eric-enm-permissions-mgr-job"]

        req.set_pubkey(server_key)
        req.sign(ca_key, "sha256")   

        server_cert = crypto.X509()
        server_cert.add_extensions([
            crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode("UTF-8")),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
            crypto.X509Extension(b"keyUsage", False, b"digitalSignature, keyEncipherment, dataEncipherment, key"),
        ])
        server_cert.gmtime_adj_notBefore(0)
        server_cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
        server_cert.set_serial_number(serialNumber)
        server_cert.set_issuer(ca_cert.get_subject())
        server_cert.set_subject(req.get_subject())
        server_cert.set_pubkey(req.get_pubkey())
        server_cert.sign(ca_key, 'sha256') 
    
        try:
            permissions_mgr_certificate_secret = """apiVersion: v1
kind: Secret
metadata:
  name: eric-enm-permissions-mgr-job-secret
  namespace: {namespace}
type: Opaque
data:
  server.crt: {server_cert}
  server.key: {server_key}
  ca.crt: {cacrt}
            """.format(
                namespace=Mapping.namespace,
                server_cert=base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert)).decode("utf-8"),
                server_key=base64.b64encode(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key)).decode("utf-8"),
                cacrt=base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)).decode("utf-8")
            )
            # update_from_yaml_single_item(k8s_client, yaml.safe_load(permissions_mgr_certificate_secret))
        except Exception as e:
            print("Failed to server certificate")
            print(e)

        client_key  = crypto.PKey()
        client_key.generate_key(crypto.TYPE_RSA, 4096)
        req = crypto.X509Req()
        req.set_version(2)
        serialNumber = randint(50000000,100000000)
        subject = req.get_subject()
        subject.commonName = "eric-enm-permissions-mgr-task"
        subject.C = "SE"
        subject.O = "ERICSSON"
        subject.OU = "BUCI_DUAC_NAM"
        subject.CN = "eric-enm-permissions-mgr-task"
        san_list = ["DNS:*.eric-enm-permissions-mgr-task", "DNS:eric-enm-permissions-mgr-task"]
        
        req.set_pubkey(client_key)
        req.sign(ca_key, "sha256")   

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
        client_cert.sign(ca_key, 'sha256') 

        try:
            permissions_mgr_certificate_secret = """apiVersion: v1
kind: Secret
metadata:
  name: permissions-mgr-task-secret
  namespace: {namespace}
type: Opaque
data:
  client.crt: {client_cert}
  client.key: {client_key}
  ca.crt: {cacrt}
            """.format(
                namespace=Mapping.namespace,
                client_cert=base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert)).decode("utf-8"),
                client_key=base64.b64encode(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key)).decode("utf-8"),
                cacrt=base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)).decode("utf-8")
            )
            # update_from_yaml_single_item(k8s_client, yaml.safe_load(permissions_mgr_certificate_secret))
        except Exception as e:
            print("Failed to server certificate")
            print(e)

    except Exception as e:
        print("test")
        print(e)

if __name__ == "__main__":

    Mapping.hostname = get_string_property_as_env(
            'HOSTNAME', Mapping.hostname)
    
    if "KUBERNETES_SERVICE_HOST" in os.environ:
        # Location of the configuration pom.xml on the remote file system
        remote_file = os.environ.get('REMOTE_FILE', 'pom2.xml')
        # Location of the configuration pom.xml on the local file system
        local_file = os.environ.get('LOCAL_FILE', '/var/configmaps/pom.yaml')
        __init = get_property_as_env('init', "False")
        if __init:
            config.load_incluster_config()
            k8s_client = client.ApiClient()
            kubernetes_cert_gen()
            exit()

    else:
        # Location of the configuration pom.xml on the remote file system
        remote_file = os.environ.get('REMOTE_FILE', 'pom2.xml')
        # Location of the configuration pom.xml on the local file system
        local_file = os.environ.get('LOCAL_FILE', 'pom.xml')

    # The xml profile to use
    print("!test-01")

    try:
        selected_profile = os.environ.get('PROFILE', "fsmap_test")
        left_tree = parse_file_as_tree(local_file)
        set_xml_profile_parameters(left_tree, selected_profile)
        left_tree = apply_properties(left_tree)
    except Exception as e:
        print(e)
    print("!test-0")

    # Ensures that all mappings run
    # (Useful for debugging or re-running in the case of network failure)
    Mapping.complete_run = get_property_as_env(
        'complete_run', Mapping.complete_run)
    # Ensures that group permissions are the same as file permissions
    Mapping.g_u_bit = get_property_as_env(
        'g_u_bit', Mapping.g_u_bit)
    # ignores user permissions on files and folders
    Mapping.ignore_user = get_property_as_env(
        'ignore_user', Mapping.ignore_user)
    # Ensures that the script runs as non root
    # (Warning this does incur a performance penalty)
    Mapping.run_as_non_root = get_property_as_env(
        'run_as_non_root', Mapping.run_as_non_root)
    # Ensures that the script runs as user
    Mapping.run_as_user = get_property_as_env(
        'run_as_user', Mapping.run_as_user)
    # Sets the sticky bit for all permissions mappings
    Mapping.sticky_bit = get_property_as_env(
        'sticky_bit', Mapping.sticky_bit)
    # Sets the set gid bit for all permissions mappings
    Mapping.setgid_bit = get_property_as_env(
        'setgid_bit', Mapping.setgid_bit)
    # Sets the set uid bit for all permissions mappings
    Mapping.setuid_bit = get_property_as_env(
        'setuid_bit', Mapping.setuid_bit)
    # Special file permissions
    Mapping.sfp = (
        (0o1000 if Mapping.sticky_bit else 0o0000) |
        (0o2000 if Mapping.setgid_bit else 0o0000) |
        (0o4000 if Mapping.setuid_bit else 0o0000)
    )
    # The default directory mode (octal string) to assign to directories
    Mapping.default_dirmode = get_numerical_property_as_env(
        'default_dirmode', Mapping.default_dirmode)
    # The default file mode (octal string) to assign to directories
    Mapping.default_filemode = get_numerical_property_as_env(
        'default_filemode', Mapping.default_filemode)
    # The default uid (uid) to assign to directories
    Mapping.default_uid = get_numerical_property_as_env(
        'default_uid', Mapping.default_uid)
    # The default gid (gid) to assign to directories
    Mapping.default_gid = get_property_as_env(
        'default_gid', Mapping.default_gid)
    Mapping.namespace = get_string_property_as_env(
        'namespace', Mapping.namespace)
    Mapping.server_port = get_numerical_property_as_env(
        'server_port', Mapping.server_port)
    
    permissions_logger.info("Running as " + Mapping.hostname)

    try:
        print("!test1")
        mappings = [Mapping(x) for x in list(left_tree.xpath('//fsmaps/fsmap[1]//mapping'))]
        if not Mapping.complete_run == "True":
            right_tree = apply_properties(parse_file_as_tree(remote_file))
            mappings2 = [Mapping(x) for x in list(right_tree.xpath('//fsmaps/fsmap[1]//mapping'))]
            print("!test2")
            for idx, mapping in enumerate(mappings):
                if mapping not in mappings2:
                    permissions_logger.info(mapping)
                    permissions_logger.info(mapping.namespace)
                    scale_on_kubernetes(idx, mapping)
                    # threading.Thread(mapping.run())


            # shutil.copyfile(local_file, remote_file)
    except Exception as e:
        permissions_logger.error(e)
        quit()


