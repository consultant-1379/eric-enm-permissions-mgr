#!/usr/bin/env bash

namespace=$1

# Extract claimName values from values.yaml file
claim_names=$(grep -o 'claimName: [^}]*' chart/eric-enm-permissions-mgr/values.yaml | cut -d' ' -f2 | sort | uniq)
echo "List of claims present in eric-enm-permissions-mgr/values.yaml: $claim_names"

echo "******Creating PVC for above claims******"
# Iterate through each claimName and create PVC
for name in $claim_names; do
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $name
  namespace: $namespace
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Mi
EOF
done

sleep 25s #Approx. time for all PVC creation completion
echo "PVC's are created in $namespace"