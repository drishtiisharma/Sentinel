# 🛡️ SENTINEL

SENTINEL is a lightweight AIOps alert-analysis console. It generates sample operational alerts, reduces repeated noise, and presents analysis such as likely root causes, service impact, security signals, and predictions. A browser-based dashboard is served by a FastAPI backend.

## ✨ Features

- Generate sample alerts or simulate a cascading incident.
- Analyze alerts using the included ML analysis pipeline.
- Review alert statistics and saved analysis history.
- Optionally add Gemini-generated summaries with an API key.
- Use the dashboard or the REST API directly.

## 📝Requirements

- Python 3.11 or newer
- pip
- Docker and Docker Compose (optional, for containerized use)

## 🚀 Run locally

From the project directory, create and activate a virtual environment, then install the dependencies:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

On macOS or Linux, use `python3 -m venv .venv`, activate with `source .venv/bin/activate`, and copy the configuration with `cp .env.example .env`.

The Gemini integration is optional. To enable it, set `GEMINI_API_KEY` in `.env`. Start the API and dashboard with:

```powershell
python -m uvicorn app:create_app --factory --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) for the dashboard. Interactive API documentation is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs), and the health endpoint is at `/health`.

## 🐳 Run with Docker Compose

Create `.env` from the example as shown above, then build and start the service:

```powershell
docker compose up --build
```

The dashboard and API are available on port `8000`. Compose persists the SQLite database under `data/` and application logs under `logs/`. Stop the service with `Ctrl+C`; run `docker compose down` to remove the stopped container.

## ⚙️ Configuration

Settings are read from environment variables or the root `.env` file. `.env.example` contains the available defaults:

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | SQLAlchemy database connection | `sqlite:///./aiops.db` |
| `GEMINI_API_KEY` | Enables Gemini-generated analysis summaries when set | Empty (disabled) |
| `SIMILARITY_THRESHOLD` | Similarity threshold used in alert analysis | `0.75` |
| `CLUSTERING_EPS` | Clustering distance parameter | `0.5` |
| `CLUSTERING_MIN_SAMPLES` | Minimum samples for clustering | `2` |
| `NOISE_REDUCTION_ENABLED` | Enables alert noise reduction | `true` |
| `REALISTIC_NOISE` | Adds repeated patterns to generated sample alerts | `true` |
| `PATTERN_REPEAT_PROBABILITY` | Probability of repeating a generated pattern | `0.3` |
| `CORS_ORIGINS` | Allowed browser origins | `["*"]` |
| `SERVE_STATIC` | Static dashboard setting | `true` |

For deployments beyond local development, set `CORS_ORIGINS` to the specific trusted origins and use an appropriately secured database and secret-management process.

## 🔍 API overview

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Service and Gemini configuration status |
| `POST` | `/generate` | Generate sample alerts |
| `POST` | `/simulate-incident` | Generate a cascading incident scenario |
| `POST` | `/analyze` | Analyze a supplied set of alerts |
| `GET` | `/stats` | Retrieve alert statistics |
| `GET` | `/history` | List saved analyses |
| `GET` | `/history/{analysis_id}` | Retrieve a saved analysis |
| `POST` | `/clear-all` | Clear stored alerts and analysis history |

See `/docs` for request schemas and interactive API testing.

## 📂 Project layout

```text
app/
  api/          Request schemas and API routes
  database/     SQLAlchemy connection, models, and repository
  ml/           Alert analysis and prediction components
  services/     Alert generation and analysis services
  utils/        Shared utilities
static/         Dashboard HTML, styles, scripts, and assets
main.py         Compatibility entry point
```
