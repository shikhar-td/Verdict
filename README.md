# Verdict

https://verdict4alert.lovable.app/ - Published URL

Verdict is an explainable SOC detection and triage project for analyzing endpoint-style logs with rules, heuristics, anomaly scoring, attack-story correlation, and entity risk ranking.

It is designed as a practical security engineering portfolio project: readable logic, clear alert explanations, realistic test datasets, and a Streamlit dashboard that makes the detection pipeline easy to inspect.

## What Verdict Does

- Ingests CSV logs with flexible column mapping
- Normalizes uploaded data into a consistent event schema
- Detects suspicious behavior using:
  - static rules
  - lightweight heuristics
  - Isolation Forest anomaly scoring
- Enriches alerts with:
  - reasons
  - explanations
  - MITRE ATT&CK mappings
  - severity and confidence
  - alert fingerprints
  - suppression state
- Correlates related alerts into higher-level attack stories
- Ranks risky entities such as processes, hosts, and users
- Stores alerts and events in SQLite instead of relying only on flat files

## Current Feature Set

### Detection

- Encoded PowerShell execution
- Suspicious Office-to-PowerShell parent-child behavior
- External IP communication
- Certutil payload retrieval
- Execution from Temp directories
- Registry Run key persistence
- Suspicious user agents
- Unusual process network behavior
- Rare process and unknown process heuristics
- Anomaly scoring with `IsolationForest`

### Triage And Context

- Severity and confidence scoring
- Fingerprints for similar alert patterns
- Rule categories such as `execution`, `network`, `persistence`, `defense_evasion`, and `anomaly`
- Suppression-aware alert display
- Correlated attack stories
- Entity risk ranking

### Data And Storage

- Flexible CSV upload
- Advanced column mapping in the dashboard
- Normalized event model
- SQLite-backed alerts and events
- Reusable synthetic dataset generators

## Architecture

```text
CSV / Uploaded Logs
        |
        v
Normalization Layer
        |
        v
Detection Engine
  - Rules
  - Heuristics
  - ML Anomaly Scoring
        |
        v
Alert Enrichment
  - Reasons
  - MITRE
  - Severity
  - Confidence
  - Fingerprint
  - Suppression State
        |
        +--> SQLite Storage
        |
        +--> Correlation Engine
        |     - Attack stories
        |
        +--> Entity Risk Engine
              - Process / host / user ranking
        |
        v
Streamlit Dashboard
```

## Project Structure

```text
Verdict-main/
|-- dashboard/              # Streamlit dashboard
|-- detection/              # Rules and suppression helpers
|-- engine/                 # Analyzer, correlation, entity risk, streaming
|-- ingestion/              # Normalization logic
|-- config/                 # Local tuning and suppression config
|-- data/                   # Sample and generated datasets
|-- scripts/                # Dataset generators
|-- tests/                  # Pytest coverage for core behavior
|-- database.py             # SQLite persistence layer
|-- models.py               # Pydantic models for events and alerts
|-- main.py                 # CLI pipeline runner
`-- requirements.txt
```

## How To Run

### 1. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Git Bash:

```bash
python -m venv .venv
source .venv/Scripts/activate
```

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Run the dashboard

```bash
python -m streamlit run dashboard/app.py
```

### 4. Run the sample CLI pipeline

```bash
python main.py
```

## Datasets

Verdict includes multiple datasets for testing:

- [data/sample_logs.csv](data/sample_logs.csv): small starter dataset
- [data/realistic_test_logs_1200.csv](data/realistic_test_logs_1200.csv): noisier large dataset for stress testing
- [data/enterprise_balanced_logs_1500.csv](data/enterprise_balanced_logs_1500.csv): better-balanced dataset with roughly 12% suspicious rows

You can generate fresh datasets with:

```bash
python scripts/generate_realistic_logs.py
python scripts/generate_balanced_enterprise_logs.py
```

## Testing

Run the test suite with:

```bash
python -m pytest -q
```

Current tests cover:

- normalization behavior
- alert deduplication and DB upserts
- suppression matching
- correlation classification

## Tech Stack

- Python
- Streamlit
- pandas
- scikit-learn
- Plotly
- SQLite
- Pydantic
- pytest

## What Makes Verdict Different

Verdict is not just a static rule demo. It tries to model the flow a junior SOC tool would need:

- flexible ingestion instead of a single fixed CSV shape
- explainable alerts instead of black-box scoring
- database-backed storage instead of temporary-only results
- attack-story correlation instead of only isolated alerts
- entity risk views instead of only per-row findings
- realistic synthetic telemetry for repeatable testing

## Limitations

- Input is still CSV-based rather than live telemetry ingestion
- Detection tuning is still noisy on some balanced datasets
- The ML layer is intentionally lightweight and not environment-trained
- Authentication, multi-user workflow, and API layers are not yet implemented

## Good Next Steps

- Reduce false positives through better baselining and tuning
- Add case management and analyst workflow
- Add FastAPI for programmatic alert access
- Add Docker for easier deployment
- Add richer endpoint and identity log adapters

## Author

Shikhar Singh
