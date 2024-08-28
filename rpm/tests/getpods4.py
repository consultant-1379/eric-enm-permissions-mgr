from kubernetes import client, config
import os
from kubernetes.client.rest import ApiException


if __name__ == "__main__":
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    config.load_kube_config("flexcenm8139.conf")

    try:
        api_instance = client.CoreV1Api()
        ret = api_instance.list_namespaced_pod("enm8139")
        for i in ret.items:            
            if "fmserv" in i.metadata.name:
                api_response = api_instance.read_namespaced_pod(i.metadata.name, i.metadata.namespace)
                print("-----"+i.metadata.name+"------")
                for container in api_response.spec.containers:
                    print("\n---"+container.name+"---") # cmserv-h
                    for volumeMount in container.volume_mounts:
                        print(volumeMount.name + "-->" + volumeMount.mount_path)
                print("\n- Pod Volumes -")
                for volume in api_response.spec.volumes:
                    print(volume.name)
                print("\n")
    except ApiException as e:
        print("Exception when calling CoreV1Api->read_namespaced_pod_log: %s\n" % e)