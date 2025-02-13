#!/usr/bin/fish

# SHA=$(git rev-parse HEAD)
set SHA $(git rev-parse HEAD)

docker build backend/ -t woragis/todos-backend:latest -t woragis/todos-backend:$SHA
docker build frontend/ -t woragis/todos-frontend:latest -t woragis/todos-frontend:$SHA

docker push woragis/todos-backend:latest
docker push woragis/todos-frontend:latest

docker push woragis/todos-backend:$SHA
docker push woragis/todos-frontend:$SHA

# kubectl apply -f k8s
kubectl set image deployments/frontend-deployment todos-frontend=woragis/todos-frontend:$SHA
kubectl set image deployments/backend-deployment todos-backend=woragis/todos-backend:$SHA
