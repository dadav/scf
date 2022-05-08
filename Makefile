.PHONY: all
all: compile-requirements

.PHONY: compile-requirements
compile-requirements:
	@find requirements -name "*.in" -print0 | xargs -0 -r -n1 pip-compile
	@pip-compile requirements.in

.PHONY: upgrade-requirements
upgrade-requirements:
	@find requirements -name "*.in" -print0 | xargs -0 -r -n1 pip-compile --upgrade
	@pip-compile --upgrade requirements.in
