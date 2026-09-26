# Unified Vulnerability Assessment Platform
# Multi-stage build: compile the React/TypeScript/Tailwind frontend first,
# then bake the static output into the Python backend image so the whole
# platform ships and runs as ONE container - no separate Node.js process
# needed at runtime.

# ---- Stage 1: build the frontend ----
FROM node:22-slim AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend .
RUN npm run build

# ---- Stage 2: backend runtime ----
FROM python:3.12-slim AS backend

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Nuclei: prebuilt binary (Go toolchain isn't in this image). Pin the
# version so builds are reproducible - bump when you want a newer engine.
ARG NUCLEI_VERSION=3.11.0
RUN curl -sL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip -d /tmp/nuclei_extract \
    && mv /tmp/nuclei_extract/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei_extract

WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist

VOLUME ["/app/backend/data"]
VOLUME ["/root/nuclei-templates"]

ENV VULN_DATABASE_URL=sqlite:////app/backend/data/vuln_platform.db
WORKDIR /app/backend

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
