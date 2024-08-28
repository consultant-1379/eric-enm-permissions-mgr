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

    try:
        api = client.CoreV1Api()
        ret = api.list_namespaced_pod("enm8139")
        count = 0
        for i in ret.items:
#            print("RWO - the i.metadata.name " + str(i.metadata.name))
            if "cts" in i.metadata.name:
                api_response = api.read_namespaced_pod(i.metadata.name, i.metadata.namespace, pretty='pretty_example')
#                print("RWO - api_response THE FULL THING" + str(api_response))
                nodeName = ""
                if api_response.spec.node_name is not None:
                  nodeName = api_response.spec.node_name
                  MappingnodeName = "\n      nodeName: " + nodeName
                  print(MappingnodeName)
                  print("\n- Pod Volumes -")
                  for volume in api_response.spec.volumes:
                     if volume.persistent_volume_claim:
                        if "cts" in volume.persistent_volume_claim.claim_name:
                          print("    - name: " + volume.name)
                          print("      persistentVolumeClaim:")
                          print("        claimName: " + volume.persistent_volume_claim.claim_name)
                print("\n     ----------------------")
        print("completed define_image() function")

# We need something like this:
#      - name: eric-enm-sso-core-token-service
#        persistentVolumeClaim:
#          claimName: eric-enm-sso-core-token-service
#      - name: eric-enm-sso-core-token-service-config
#        persistentVolumeClaim:
#          claimName: eric-enm-sso-core-token-service-config
#      - name: eric-enm-sso-core-token-service-changelog
#        persistentVolumeClaim:
#          claimName: eric-enm-sso-core-token-service-changelog
    except ApiException as e:
        print("Exception when calling CoreV1Api->read_namespaced_pod_log: %s\n" % e)
