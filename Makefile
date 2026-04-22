.PHONY: bootstrap up down demo clean clean-artifacts

bootstrap:
	docker pull python:3.12-slim
	@echo "Bootstrap complete. Run 'make up' to start the environment."
	
up:
	docker-compose up -d --build

down:
	docker-compose down

demo:
	docker run --rm \
		-v "$(PWD)/artifacts/release:/app/artifacts/release" \
		tls-auditor python src/auditor.py google.com

clean:
	docker-compose down --rmi all --volumes --remove-orphans

clean-artifacts:
	rm -f artifacts/release/*.json artifacts/release/*.csv
	@echo "Artifacts cleared."