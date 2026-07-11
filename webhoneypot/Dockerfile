FROM python:3.12-slim

WORKDIR /srv
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

COPY app.py .

EXPOSE 80
# stdlib-only sensor — no dependencies to install
CMD ["python", "app.py"]
