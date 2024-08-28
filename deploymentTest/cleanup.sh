#!/usr/bin/env bash

namespace=$1
doesNSExist=$(/usr/local/bin/kubectl get ns "$namespace")

#Creates new namespace if it doesn't exist else delete existing namespace and create new.
if [[ "$doesNSExist" == "" ]]; then
    echo "$1 namespace doesnt exist."
    /usr/local/bin/kubectl create ns "$namespace"
    echo "Created namespace $namespace"
else
    echo "$1 namespace exists"
    /usr/local/bin/kubectl delete ns "$namespace"
    /usr/local/bin/kubectl create ns "$namespace"
    echo "Deleted and Recreated namespace $namespace"
fi