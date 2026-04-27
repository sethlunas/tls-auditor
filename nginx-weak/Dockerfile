FROM python:3.8-slim

WORKDIR /app

# copy only what the weak server needs
COPY src/weak_server.py ./src/
COPY nginx-weak/certs /app/nginx-weak/certs

# run the weak test server on startup
CMD ["python", "src/weak_server.py"]