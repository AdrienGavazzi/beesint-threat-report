FROM python:3.11-slim

# Couche 1 : dépendances système Pango/Cairo/Harfbuzz — change rarement, en premier pour le cache Docker
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz-subset0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Couche 2 : dépendances Python — invalidée seulement si requirements.txt change
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Couche 3 : code applicatif — couche la plus volatile, en dernier
COPY . .
RUN pip install --no-cache-dir -e .

CMD ["python", "-m", "beesint_threat_report.orchestrate"]
