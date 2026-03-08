.PHONY: help verify check acceptance pressure

help:
	@printf '%s\n' \
	  'Available targets:' \
	  '  make verify      Run local verification checks' \
	  '  make check       Alias of make verify' \
	  '  make acceptance  Run phase4 acceptance regression' \
	  '  make pressure    Run phase4 pressure sample'

verify:
	./scripts/verify.sh

check: verify

acceptance:
	./scripts/phase4_acceptance.sh

pressure:
	./scripts/phase4_pressure_sample.sh
