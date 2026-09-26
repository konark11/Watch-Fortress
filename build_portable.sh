#!/usr/bin/env bash
# build_portable.sh
#
# Run this ON A CONNECTED MACHINE to produce everything needed to carry
# the Unified Vulnerability Assessment Platform across an air gap:
#   1. A Docker image saved as a .tar (docker load'able with zero internet)
#   2. A local nuclei-templates snapshot (nuclei itself needs no network
#      once templates are present locally)
#   3. A local pip wheel cache, for the non-Docker deployment path
#
# Usage: ./build_portable.sh [output_dir]

set -euo pipefail
OUT_DIR="${1:-./portable_build}"
mkdir -p "$OUT_DIR"

echo "[1/4] Building frontend + backend Docker image..."
docker build -t vuln-platform:offline .

echo "[2/4] Saving Docker image to $OUT_DIR/vuln-platform-image.tar ..."
docker save vuln-platform:offline -o "$OUT_DIR/vuln-platform-image.tar"

echo "[3/4] Snapshotting nuclei-templates for offline transport..."
if [ ! -d "$HOME/nuclei-templates" ]; then
  git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$HOME/nuclei-templates"
fi
tar -czf "$OUT_DIR/nuclei-templates.tar.gz" -C "$HOME" nuclei-templates

echo "[4/4] Downloading pip wheels for offline install (non-Docker path)..."
mkdir -p "$OUT_DIR/wheels"
pip download -r backend/requirements.txt -d "$OUT_DIR/wheels"

cp -r backend "$OUT_DIR/"
cp -r frontend/dist "$OUT_DIR/frontend_dist" 2>/dev/null || echo "  (run 'npm run build' in frontend/ first if frontend_dist is missing)"

cat > "$OUT_DIR/INSTALL_AIRGAPPED.md" << 'EOF'
# Installing on the air-gapped machine

## Option A: Docker (recommended)
    docker load -i vuln-platform-image.tar
    mkdir -p ~/nuclei-templates && tar -xzf nuclei-templates.tar.gz -C ~
    docker run -d -p 8000:8000 \
      -v vuln-data:/app/backend/data \
      -v ~/nuclei-templates:/root/nuclei-templates \
      --cap-add=NET_RAW --cap-add=NET_ADMIN \
      vuln-platform:offline

## Option B: Python venv (no Docker)
    tar -xzf nuclei-templates.tar.gz -C ~
    python3 -m venv venv
    source venv/bin/activate
    pip install --no-index --find-links wheels/ -r backend/requirements.txt
    cp -r frontend_dist backend/../frontend/dist
    cd backend && uvicorn main:app --host 0.0.0.0 --port 8000

Then open http://<machine-ip>:8000 and use the "Create the administrator
account" flow on first launch. No internet access is required for either
path. OpenVAS and Nessus scanners will show as unavailable until you point
GVM_HOST/NESSUS_URL at a real instance on your internal network - Nmap and
Nuclei work immediately using the templates carried across in this bundle.
EOF

echo "Done. Copy the '$OUT_DIR' directory to removable media."
