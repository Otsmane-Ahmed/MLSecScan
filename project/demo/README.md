# Demo environment (DVWA) for MLSecScan

This demo uses DVWA (Damn Vulnerable Web Application) running locally in Docker.

Steps to run demo:

1. From project/ directory:
   cd project/demo
   docker compose up -d

2. Wait until DVWA is up. Open in browser:
   http://localhost:8000

3. From the project root (~/MLSecScan):
   # activate venv (if you want)
   python3 -m venv .venv || true
   source .venv/bin/activate
   pip install -r requirements.txt

   # run the scanner against the local DVWA
   python3 v8.py --url http://localhost:8000 --depth 2 --threads 3 --output-dir demo/output --no-tor

4. Reports will be written to project/demo/output (create this folder if missing).

Notes:
- **Do not** run the scanner against external/public websites. This demo intentionally uses local DVWA.
- If port 8000 is in use, change the left side of the mapping (e.g. "8080:80") in docker-compose.yml and use that port in the scanner URL.
