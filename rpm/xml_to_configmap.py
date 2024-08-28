import sys
import json
import os
import yaml
from re import sub
import re
import xml.etree.ElementTree as ET

XML_NODE_CONTENT = "text"
ATTR_COMMENT = "# Attribute"
DIRECTORY = 'directory'
PROPERTIES = 'properties'
PROFILE = 'profile'
PREDEPLOY_VALUE_YAML = "../chart/eric-enm-permissions-mgr/values.yaml"
STATELESS_VALUE_YAML = "../chart/eric-enm-permissions-mgr-stateless/values.yaml"
PERMISSION_MGR_CONFIGS = ".Values.permissionMgrConfigs."
CONFIG_PERMISSIONS = "permissionMgrConfigs"
JOB_PERMISSIONS = "permissionsMgrJob"
DELIMETER='_'
MAPPING = "mapping"
BREAKPOINT = "breakpoint"
VOLUME_MOUNTS = "volumeMounts"
VOLUMES = "volumes"
FSMAP = "fsmap"
namespace = "namespace"
APP_NAME = "eric-enm-permissions-mgr"

if len(sys.argv) != 3:
    print("Executing the xml_to_configmap script")
    sys.stderr.write("Usage: {0} <file>.xml".format(sys.argv[0])+ " output_yaml_filename")

class xml_to_configmap():
    def __init__(self, DIR_NAME="default", depth=0, values_map ={}):
        self.DIR_NAME = DIR_NAME
        self.depth = depth
        self.values_map = values_map
        self.isMappingTagSet = False
        self.isBreakpointTagSet = False
        self.model_breakpoint = set()
        self.fsmap_counter = 1

def get_configmap_template(instance):
    instance.values_map["metadata_name"] = APP_NAME
    return """apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ template "eric-enm-permissions-mgr.name" . }}-configmap
  labels: {{- include "eric-enm-permissions-mgr.labels" . | nindent 4 }}
  annotations:
    "helm.sh/hook": pre-install,pre-upgrade
    "helm.sh/hook-weight": "-6"
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
  {{- include "eric-enm-permissions-mgr.annotations" . | nindent 4 }}
data:
    pom.yaml: |
    """

def get_snake_to_camel(name):
    name = sub(r"(_|-)+", " ", name).title().replace(" ", "")
    return ''.join([name[0].lower(), name[1:]])

def get_camel_to_snake(name):
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()

def get_configmap_data(node, depth, instance):
        # Nodes with both content AND nested nodes or attributes
        # have no valid yaml mapping. Add  'content' node for that case
        nodeattrs = node.attrib
        children = list(node)
        content = node.text.strip() if node.text else ""

        if node.tag == MAPPING:
            
            for child in children:
                print(child.tag)
                if child.tag == DIRECTORY: 
                    lcontent = child.text.strip() if child.text else ""
                    instance.DIR_NAME = lcontent.replace('/',DELIMETER).replace(DELIMETER, '', 1)
                    instance.depth = depth
            
            if not instance.isMappingTagSet:
                configmap.write("{indent}{tag}:\n".format(indent=depth * "  ", tag=get_camel_to_snake(node.tag)))
                instance.isMappingTagSet = True
            configmap.write("{indent} -\n".format(indent=depth * "  "))
            depth += 3
            for child in children:
                get_configmap_data(child, depth, instance)
            return
        elif node.tag == "nfsparameters":           
            instance.DIR_NAME = "nfsparameters"
            configmap.write("{indent}{tag}:\n".format(indent=depth * "  ", tag=node.tag))
            depth += 3
            instance.isBreakpointTagSet = False
                    # Write nested nodes
            for child in children:
                get_configmap_data(child, depth, instance)
            return
        elif node.tag == DIRECTORY: 
            instance.DIR_NAME = content.replace('/',DELIMETER).replace(DELIMETER, '', 1)
            instance.depth = depth
            print("---")

        instance.DIR_NAME = node.tag if depth < instance.depth else instance.DIR_NAME
        instance.DIR_NAME = PROPERTIES if node.tag == PROPERTIES else instance.DIR_NAME
        instance.DIR_NAME = PROFILE if node.tag == PROFILE else instance.DIR_NAME

        if content :
            if not (nodeattrs or children):
                if (node.tag == "namespace"):
                    configmap.write(
                        "{indent}{tag}: {text}\n".format(
                            indent=depth * "  ",
                            tag=get_camel_to_snake(node.tag),
                            text="{{ .Release.Namespace | default \"" + content + "\" | quote }}",
                        )
                    )
                    instance.values_map["metadata_namespace"] = content
                    return
                else:
                    # print(instance.DIR_NAME)
                    # Write as just a name value, nothing else nested
                    configmap.write(
                        "{indent}{tag}: {text}\n".format(
                            indent=depth * "  ",
                            tag=get_camel_to_snake(node.tag),
                            text="{{ "+PERMISSION_MGR_CONFIGS+instance.DIR_NAME+DELIMETER+get_camel_to_snake(node.tag) + '| default \"'+content+"\" | quote "+" }}" or "",
                        )
                    )
                    instance.values_map[instance.DIR_NAME+'_'+get_camel_to_snake(node.tag)] =  content
                    return
            else:
                nodeattrs[XML_NODE_CONTENT] = json.dumps(node.text)    
       
        if(node.tag == FSMAP):
            if(instance.fsmap_counter == 1):
                configmap.write("{indent}fsmap:\n".format(indent=depth * "  "))
                node.tag = FSMAP 
                instance.fsmap_counter = 2
            else :
                instance.isMappingTagSet = False
                node.tag = FSMAP 
       
        if(node.tag == BREAKPOINT or node.tag == FSMAP):
            if(node.tag == BREAKPOINT and instance.isBreakpointTagSet == False):
                configmap.write("{indent}{tag}:\n".format(indent=depth * "  ", tag=get_camel_to_snake(node.tag)))
                configmap.write("{indent} -\n".format(indent=depth * "  "))
                instance.isBreakpointTagSet = True
            else:
                configmap.write("{indent} -\n".format(indent=depth * "  "))
        else:
            configmap.write("{indent}{tag}:\n".format(indent=depth * "  ", tag=node.tag))
            instance.isBreakpointTagSet = False

        # Indicate difference node attributes and nested nodes
        depth += 3
        for n, v in nodeattrs.items():
            prefix = "#" if n == "text" else "-" 
            instance.model_breakpoint.add(v.strip('"').split("/models/")[0]) if n == "text" else ""
            configmap.write(
                "{indent}{n}: {v}\n".format(
                    indent=depth * "  ",
                    n=json.dumps(prefix+n),
                    v=v,
                    c=ATTR_COMMENT if n != XML_NODE_CONTENT else "",
                )
            )
        # Write nested nodes
        for child in children:
            get_configmap_data(child, depth, instance)

# Read pom.xml file and parse it
with open(sys.argv[1]) as xmlf:
    tree = ET.parse(xmlf)
    instance = xml_to_configmap()

# create configmap and update the data into configmap 
with open(sys.argv[2], "w") as configmap:
    instance = xml_to_configmap()
    configmap.write(get_configmap_template(instance))
    get_configmap_data(tree.getroot(), 1, instance)
    
# update values.yaml file
with open (PREDEPLOY_VALUE_YAML, mode = "r") as read_file:
    values_yaml_file = yaml.safe_load(read_file)
    values_yaml_file[JOB_PERMISSIONS].update({"volumesUG":[]})
    values_yaml_file[JOB_PERMISSIONS].update({"volumeMountUG":[]})
    current_mounts_ug = values_yaml_file[JOB_PERMISSIONS]["volumeMountUG"]
    current_volumes_ug = values_yaml_file[JOB_PERMISSIONS]["volumesUG"]
    for bp_count, bp in enumerate(instance.model_breakpoint, start=1):
        bp_mount = {'mountPath': bp,'name': 'breakpoint-'+str(bp_count)}
        bp_volume = {'name': 'breakpoint-'+str(bp_count),'hostPath': {'path': bp}}
        current_mount_bp = ""
        print("Mount : "+str(bp_mount))
        print("Volume : "+str(bp_volume))
        # Use unique keys for each mount and volume
        current_mounts_ug.append(bp_mount)
        current_volumes_ug.append(bp_volume)
    values_yaml_file.update({CONFIG_PERMISSIONS: instance.values_map})
# Dump the value yaml data into the file
with open(PREDEPLOY_VALUE_YAML,'w') as yamlfile:
    # Updating the predeploy chart values yaml file
    yaml.safe_dump(values_yaml_file, yamlfile)
