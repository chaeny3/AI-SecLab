# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

응답은 한국어로 해줘.

## Project

Flask web app that classifies uploaded PE (`.exe`) files as malicious or benign using a RandomForest model trained on PE structural features (entropy, sections, imports). UI strings and JSON error messages are in Korean.

## Running

1. `pip install -r requirements.txt`
2. Model must exist at `models/pe_classifier.pkl` (gitignored, not checked in). To regenerate:
   - `python data_collector.py` — pulls benign `.exe` files from `C:\Windows\System32` (**Windows-only**, hardcoded path)
   - `python malware_simulator.py` — generates synthetic malicious feature vectors (seeded, `random.seed(42)`)
   - `python train_model.py` — trains and saves `models/pe_classifier.pkl` + `models/confusion_matrix.png`
3. `python app.py` — serves on port 5000. Debug mode is off by default; set `FLASK_DEBUG=1` to enable the Werkzeug debugger locally (never enable it if the app is reachable outside localhost — it allows arbitrary code execution).

No test suite, linter, or formatter is configured.

## Sample data policy

Training/test data must stay synthetic (`malware_simulator.py`) or drawn from legitimate system binaries (`data_collector.py`). Do not commit real malware samples to this repo. `data/*.exe` is gitignored — uploads via `/analyze` land at the fixed path `data/upload_temp.exe` and are overwritten on each request; don't treat that file as persistent or safe to execute.

## Architecture

- `analyzer/pe_analyzer.py` — pefile-based parsing (sections, entropy, import table); also runnable standalone as a CLI
- `app.py` — Flask routes (`/`, `/analyze`), loads the pickled model, extracts feature vector, returns prediction + probability
- `data_collector.py` / `malware_simulator.py` / `train_model.py` — offline pipeline to build `data/*.csv` and train the model
