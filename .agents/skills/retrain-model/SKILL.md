---
name: retrain-model
description: Regenerate training data and retrain the PE classifier model (models/pe_classifier.pkl). Use when the model is missing, stale, or training data has changed.
---

Run these three steps in order from the repo root:

1. `python data_collector.py` — collects benign `.exe` samples from `C:\Windows\System32` (Windows-only). Produces/updates `data/benign_features.csv`.
2. `python malware_simulator.py` — generates synthetic malicious feature vectors (seeded, `random.seed(42)`). Produces/updates `data/malware_features.csv`. Never substitute real malware samples here — see the sample data policy in AGENTS.md.
3. `python train_model.py` — trains a RandomForest on the combined features and writes `models/pe_classifier.pkl` and `models/confusion_matrix.png`.

After training, restart `app.py` (it loads the model once at import time) if it was already running.
