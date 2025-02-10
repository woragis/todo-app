#!/usr/bin/fish

docker build backend/ -t woragis/todos-backend

docker build frontend/ -t woragis/todos-frontend

docker push woragis/todos-backend

docker push woragis/todos-frontend