# declares all targets as phony - tells Make these are commands, not filenames
.PHONY: bootstrap up down demo clean clean-artifacts test

# pulls the base Python image to cache it locally - run once before anything else
bootstrap:
	docker pull python:3.12-slim
	@echo "Bootstrap complete. Run 'make up' to start the environment."

# builds and starts all containers in the background using docker-compose
up:
	docker-compose up -d --build

# stops and removes all running containers
down:
	docker-compose down

# runs the TLS auditor against both test servers and saves reports to artifacts/release/
# host.docker.internal lets the container reach ports on the Mac's localhost
# 8443 = weak server (TLS 1.0/1.1), 9443 = hardened server (TLS 1.2/1.3)
demo:
	docker run --rm \
		-v "$(PWD)/artifacts/release:/app/artifacts/release" \
		tls-auditor python src/auditor.py host.docker.internal 8443
	docker run --rm \
		-v "$(PWD)/artifacts/release:/app/artifacts/release" \
		tls-auditor python src/auditor.py host.docker.internal 9443

# tears down all containers, images, volumes, and orphaned services
clean:
	docker-compose down --rmi all --volumes --remove-orphans

# removes all generated JSON and CSV report files from artifacts/release/
clean-artifacts:
	rm -f artifacts/release/*.json artifacts/release/*.csv
	@echo "Artifacts cleared."

# runs all unit tests with verbose output
test:
	pytest tests/test_auditor.py -v 
