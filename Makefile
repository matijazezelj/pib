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

# The password file itself stays group/other-readable: step-ca reads it as
# uid 1000 from inside the container, so chmod 600 would break CA init on any
# host whose uid differs. Restricting the directory blocks other local users
# just as effectively, and works regardless of uid.
ca-password:
	@chmod 700 ca
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
