#!/usr/bin/fish

docker run -d -p 80:80 woragis/todos-frontend:latest
docker run -d -p 8080:8080 woragis/todos-backend:latest
