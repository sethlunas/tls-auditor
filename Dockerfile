# Pulls a minimal Linux environment with Python pre-installed
FROM python:3.12-slim

# sets working directory inside container
WORKDIR /app

# copies requirements file from machine to container
COPY requirements.txt .

# install python dependencies to container and skips caching 
RUN pip install --no-cache-dir -r requirements.txt

# copy source code from machine to container
COPY src/ ./src/

# default command that runs when the container starts
CMD ["python", "src/auditor.py"]