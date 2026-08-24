.PHONY: install lock up down status logs topics \
        produce-nvd produce-epss produce-kev consume validate \
        silver gold train score jupyter clean-generated

# ── Dependencies ──────────────────────────────────────────────────────────────
install:           ## Sync the virtualenv with all extras
	uv sync --all-extras

lock:              ## Regenerate uv.lock
	uv lock

# ── Docker Compose ────────────────────────────────────────────────────────────
up:                ## Start Kafka + UI + service containers
	docker compose up -d

down:              ## Stop all containers
	docker compose down

status:
	docker compose ps

logs:
	docker compose logs -f

# ── Kafka ─────────────────────────────────────────────────────────────────────
topics:            ## Create all Kafka topics
	docker compose exec ingestion python -m riskrank.kafka.admin

# ── Ingestion (run inside the ingestion container) ────────────────────────────
produce-nvd:       ## Read the local OSV corpus (data/raw_osv) -> Kafka
	docker compose exec ingestion python -m riskrank.producers.nvd

produce-epss:
	docker compose exec ingestion python -m riskrank.producers.epss --lookback-days 180

produce-kev:
	docker compose exec ingestion python -m riskrank.producers.kev

consume:
	docker compose exec consumer python -m riskrank.consumers.file_sink --source all --until-idle 30

validate:
	docker compose exec consumer python -m riskrank.consumers.validate

# ── Spark + models (run inside the jupyter container, which has PySpark) ───────
silver:
	docker compose exec jupyter python -m riskrank.spark.silver

gold:
	docker compose exec jupyter python -m riskrank.spark.gold

train:
	docker compose exec jupyter python -m riskrank.models.train

score:             ## make score VECTOR="CVSS:3.1/AV:N/..." BASE=7.0
	docker compose exec jupyter python -m riskrank.models.scoring --vector "$(VECTOR)" --base-score $(BASE)

jupyter:           ## Print the JupyterLab URL
	@echo "JupyterLab: http://localhost:8888/?token=$${JUPYTER_TOKEN:-riskrank}"

# ── Housekeeping ──────────────────────────────────────────────────────────────
clean-generated:   ## Delete Bronze/Silver/Gold/checkpoints/models/reports (keep .gitkeep)
	find data -mindepth 1 -not -name '.gitkeep' -delete
