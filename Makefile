SHELL := /bin/bash

.PHONY: up down logs build test dev-browser

up:
	docker compose -f docker-compose.test.yml up -d

down:
	docker compose -f docker-compose.test.yml down --remove-orphans

logs:
	docker compose -f docker-compose.test.yml logs -f postgres

build:
	npm run build

test:
	npm test

dev-browser:
	npm run dev --workspace=packages/browser-ui
