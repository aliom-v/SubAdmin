.PHONY: help up gateway-up down ps logs verify check acceptance pressure

help:
	@printf '%s\n' \
	  'Available targets:' \
	  '  make up          Start compose stack (api/web/sublink)' \
	  '  make gateway-up  Start gateway profile with caddy' \
	  '  make down        Stop stack and remove volumes/orphans' \
	  '  make ps          Show compose service status' \
	  '  make logs        Show recent compose logs (SERVICE=<name> optional)' \
	  '  make verify      Run local verification checks' \
	  '  make check       Alias of make verify' \
	  '  make acceptance  Run phase4 acceptance regression' \
	  '  make pressure    Run phase4 pressure sample'

up:
	docker compose up -d --build api web sublink

gateway-up:
	docker compose --profile gateway up -d --build

down:
	docker compose down -v --remove-orphans

ps:
	docker compose ps

logs:
	@if [ -n "$(SERVICE)" ]; then \
		docker compose logs --tail=200 "$(SERVICE)"; \
	else \
		docker compose logs --tail=200 api web sublink; \
	fi

verify:
	./scripts/verify.sh

check: verify

acceptance:
	./scripts/phase4_acceptance.sh

pressure:
	./scripts/phase4_pressure_sample.sh
