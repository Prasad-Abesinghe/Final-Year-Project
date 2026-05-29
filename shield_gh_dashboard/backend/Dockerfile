FROM python:3.12-slim

WORKDIR /app/shield_gh_dashboard/backend

COPY shield_gh_dashboard/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shield_gh_dashboard/backend/main.py .

EXPOSE 8000

# main.py uses Path(__file__).parent.parent.parent == /app (project root)
# Volumes for bc and fl output are mounted at /app/shield_gh_blockchain/output
# and /app/shield_gh_fl/output by docker-compose
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
