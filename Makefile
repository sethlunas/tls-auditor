.PHONY: bootstrap up down demo clean

bootstrap:
	docker pull python:3.12-slim
	@echo "Bootstrap complete. Run 'make up' to start the environment."
	
up:
	docker-compose up -d --build

down:
	docker-compose down

demo:
	@echo "Demo target not yet implemented."

clean:
	docker-compose down --rmi all --volumes --remove-orphans