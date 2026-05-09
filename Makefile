.PHONY: setup check migrate test run launch docker-up

setup:
	python -m megido_security.setup --skip-docker

check:
	USE_SQLITE=true python manage.py check

migrate:
	USE_SQLITE=true python manage.py migrate --noinput

test:
	python -m pytest -q test_*.py

run:
	USE_SQLITE=true python manage.py runserver

launch:
	python launch.py

docker-up:
	docker compose up --build
