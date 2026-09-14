FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/forge

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .[server]

EXPOSE 8010

CMD ["sneppx-forge", "serve", "--host", "0.0.0.0", "--port", "8010"]