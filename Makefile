.PHONY: up down restart logs build scan-now clean ca-password ca-fingerprint

up: ca-password
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

build:
	docker compose build --no-cache

logs:
	docker compose logs -f

scan-now:
	docker exec pib-monitor python /app/monitor.py --once

ca-password:
	@if [ ! -f ca/password.txt ]; then \
		echo "Generating CA password..." ; \
		openssl rand -base64 32 > ca/password.txt ; \
		echo "CA password written to ca/password.txt — keep this safe!" ; \
	fi

ca-fingerprint:
	@docker exec pib-ca step certificate fingerprint /home/step/certs/root_ca.crt

clean:
	docker compose down -v
	docker rmi pib-monitor 2>/dev/null || true
