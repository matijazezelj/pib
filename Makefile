.PHONY: up down build logs ps check-now restart clean

up:
	docker compose up -d

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

ps:
	docker compose ps

check-now:
	docker exec pib-tracker python /app/tracker.py --once

restart:
	docker compose restart pib-tracker

clean:
	docker compose down -v
