.DEFAULT_GOAL := help

## -- HELP --

## This help message
## Which can also be multiline
.PHONY: help
help:
	@printf "Usage\n";

	@awk '{ \
			if ($$0 ~ /^.PHONY: [a-zA-Z\-\/\_0-9]+$$/) { \
				helpCommand = substr($$0, index($$0, ":") + 2); \
				if (helpMessage) { \
					printf "\033[36m%-20s\033[0m %s\n", \
						helpCommand, helpMessage; \
					helpMessage = ""; \
				} \
			} else if ($$0 ~ /^[a-zA-Z\-\/\_0-9.]+:/) { \
				helpCommand = substr($$0, 0, index($$0, ":")); \
				if (helpMessage) { \
					printf "\033[36m%-20s\033[0m %s\n", \
						helpCommand, helpMessage; \
					helpMessage = ""; \
				} \
			} else if ($$0 ~ /^##/) { \
				if (helpMessage) { \
					helpMessage = helpMessage"\n                     "substr($$0, 3); \
				} else { \
					helpMessage = substr($$0, 3); \
				} \
			} else { \
				if (helpMessage) { \
					print "\n                     "helpMessage"\n" \
				} \
				helpMessage = ""; \
			} \
		}' \
		$(MAKEFILE_LIST)


## -- Docker --

## Start full stack with MySql
.PHONY: stack/up
stack/up:
	docker-compose up

## SSH into keycloak container
.PHONY: stack/ssh-kc
stack/ssh-kc:
	docker-compose exec keycloak -it bash

## -- Development --

## Start Keycloak in debug mode using h2
.PHONY: debug
debug:
	docker-compose -f docker-compose-dev.yml up

## Create realm into keycloak
.PHONY: realm/create
realm/create:
	docker-compose exec keycloak \
	/opt/jboss/keycloak/bin/kcadm.sh create realms -s enabled=true -f /tmp/demo-realm.json --no-config --server http://localhost:8080/auth --realm master --user admin --password admin

## Delete realm into keycloak
.PHONY: realm/delete
realm/delete:
	docker-compose exec keycloak \
	/opt/jboss/keycloak/bin/kcadm.sh delete realms/demo --no-config --server http://localhost:8080/auth --realm master --user admin --password admin

## Delete realm into keycloak
.PHONY: realm/reload
realm/reload: realm/delete realm/create

## Build local project modules
.PHONY: mvn/install
mvn/install:
	(mvn clean install -DskipTests)

## Build authenticator providers only
.PHONY: mvn/install-auth-provider
mvn/install-auth-provider:
	(cd ./authenticator-jar-module && mvn clean install -DskipTests)

## Deploy authenticator providers only
.PHONY: mvn/deploy-auth-provider
mvn/deploy-auth-provider:
	(cd ./authenticator-ear-module && mvn clean wildfly:deploy -Dwildfly.username=keycloak -Dwildfly.password=keycloak)

## Get a token using password
.PHONY: kc/login
kc/login:
	./test-direct-grant.sh

## Show openid info page
.PHONY: kc/info
kc/info:
	curl -v -k http://localhost:8080/auth/realms/demo/.well-known/openid-configuration  | jq '.'

## -- Tools --

## Show info about the project
.PHONY: info
info:
	@echo "Account url http://localhost/auth/realms/demo/account/"
	@echo "Account url http://localhost/auth/realms/demo/protocol/openid-connect/logout"



