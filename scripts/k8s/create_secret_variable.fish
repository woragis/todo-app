#!/usr/bin/fish

# kubectl create secret generic pgpassword --from-literal=PGPASSWORD=mysecurepassword
kubectl create secret generic $1 --from-literal=$2=$3
