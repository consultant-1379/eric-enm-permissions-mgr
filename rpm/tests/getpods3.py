from kubernetes import client, config
import os
from kubernetes.client.rest import ApiException


# Configs can be set in Configuration class directly or using helper utility



# if __name__ == "__main__":
#     v1 = client.CoreV1Api()
    

#     print("watching pod status:")
#     count = 0
#     ret = v1.list_namespaced_pod("enm8139")
#     for i in ret.items:
#         if "cmserv" in i.metadata.name:
#             count = count + 1
#             print("%s\t%s\t%s" % (i.metadata.namespace, i.metadata.name, i.status.phase))
#     print(count)
 
if __name__ == "__main__":
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    config.load_kube_config("flexcenm8139.conf")

    try:
        api_instance = client.CoreV1Api()
        ret = api_instance.list_namespaced_pod("enm8139")
        count = 0 
        for i in ret.items:
            if "permissions" in i.metadata.name:
                count = count + 1
                api_response = api_instance.read_namespaced_pod(i.metadata.name, i.metadata.namespace)

                if api_response.spec.node_selector is not None:
                  for label in api_response.spec.node_selector:
                      print(label + ":" + api_response.spec.node_selector[label])
                if api_response.metadata.labels is not None:
                  for label in api_response.metadata.labels:
                      print(label + ":" + api_response.metadata.labels[label])
                print("-----------")
                for label in api_response.metadata.annotations:
                    print(label + ":" + api_response.metadata.annotations[label])

# metadata:
#   annotations:
#     ericsson.com/product-name: Permissions Manager
#     ericsson.com/product-number: CXD 101 1001
#     ericsson.com/product-revision: 1.0.0
#     meta.helm.sh/release-name: eric-enm-pre-deploy-integration-enm8139
#     meta.helm.sh/release-namespace: enm8139
#   creationTimestamp: "2023-06-09T14:21:08Z"
#   labels:
#     app.kubernetes.io/instance: eric-enm-pre-deploy-integration-enm8139
#     app.kubernetes.io/managed-by: Helm
#     app.kubernetes.io/name: eric-enm-permissions-mgr
#     app.kubernetes.io/version: 1.0.0-1
#     chart: eric-enm-permissions-mgr-1.0.0-1
#     helm.sh/chart: eric-enm-permissions-mgr-1.0.0-1
#   name: eric-enm-permissions-mgr-filestore-secret
#   namespace: enm8139
#   resourceVersion: "66376820"
#   uid: 7a70617f-d46d-43be-a24a-35892d334287

    except ApiException as e:
        print("Exception when calling CoreV1Api->read_namespaced_pod_log: %s\n" % e)