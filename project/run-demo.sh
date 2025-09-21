#!/usr/bin/env bash
set -e
# Run DVWA locally and the scanner against it (reproducible demo)
cd "$(dirname "$0")"
cd demo
docker compose up -d
cd ..
# create venv if missing and install deps
python3 -m venv .venv || true
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
# run the scanner (adjust flags if your CLI differs)
python3 v8.py --url http://localhost:8000 --depth 2 --threads 3 --output-dir demo/output --no-tor
echo "Done. Check project/demo/output for reports."
