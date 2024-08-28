from kubernetes import client, config
import os
from kubernetes.client.rest import ApiException

# This runs on a vapp - 2788 was used perviously
# Use this page for steps to setup the config key file
# https://eteamspace.internal.ericsson.com/display/ITP/Using+Permisions-mgr+scripts+from+vapp+2788
#

if __name__ == "__main__":
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    config.load_kube_config("config")

#  Test input mounts - need to be able to handle 1 to many
#    
#    configMapMountPath="/opt/ericsson/sso/opends/changelogDb"
#    configMapMountPath="/opt/ericsson/sso/opends/changelogDb,/opt/ericsson/sso/opends/config"
    configMapMountPath="/opt/ericsson/sso/opends/db,/opt/ericsson/sso/opends/config,/opt/ericsson/sso/opends/changelogDb"

    if "," in configMapMountPath:
       print("There are multiple mount paths " + configMapMountPath)
       idxes = configMapMountPath.split(",")
       numberItems=len(idxes)
       print("There are " + str(numberItems))
       count=0
       mount_path=""
       for index in idxes:
           count=count+1
           mount_path = mount_path + (index + "\n")
           if (count != numberItems):
              mount_path = mount_path + ("          name: mnt" + str(count) + "\n" + "        - mountPath: ")
    else:
       mount_path=str(configMapMountPath)
    print(mount_path)

    try:
        api = client.CoreV1Api()
        ret = api.list_namespaced_pod("enm8139")

# Test input mounts - need to be able to handle 1 to many
# readWriteOnce is the SG name 
# The claims need to be matched like the mounts above 
# <claim_name>changelogDb-config-db</claim_name>
        
        readWriteOnce="cts-"
        claim_name=""
        MappingnodeName=""
        MappingclaimName=""
        tempClaim=""
        count = 0
        if readWriteOnce.lower() != "false":
#           print("readWriteOnce is not false")
           for i in ret.items:
#               if readWriteOnce in i.metadata.name:
               if str(i.metadata.name).startswith(str(readWriteOnce)):
                  print("readWriteOnce matches name")
                  print(str(i.metadata.name) + " starts with " + str(readWriteOnce))
                  api_response = api.read_namespaced_pod(i.metadata.name, i.metadata.namespace, pretty='pretty_example')
#                 print(" api_response THE FULL THING" + str(api_response))
                  nodeName = ""
                  if api_response.spec.node_name is not None:
                     MappingnodeName = api_response.spec.node_name
                     print(MappingnodeName)
                     tempClaim=[]
                     for volume in api_response.spec.volumes:
                        if volume.persistent_volume_claim:
                           if readWriteOnce in volume.persistent_volume_claim.claim_name:
                              tempClaim.append(volume.persistent_volume_claim.claim_name) 
                     print("Here are the claims - " + str(tempClaim))
                     count=0
                     claim_name=""
                     last_item = tempClaim[-1]
                     for index in tempClaim:
                            count=count+1
                            claim_name = claim_name + (index)
                            if (index == last_item):
                               pass
                            else:
                               claim_name = claim_name + "\n" + "      - name: mnt" + str(count) + "\n"
                               claim_name = claim_name + "        persistentVolumeClaim:\n" + "          claimName: "
                  print(claim_name)
                              
        print("\ncompleted test mount nodename claim preparation\n")

# Print out mount_path, nodename and the claim_name for RWO mappings
    except ApiException as e:
        print("Exception when calling CoreV1Api->read_namespaced_pod_log: %s\n" % e)
