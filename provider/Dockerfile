# Atesta wallet provider (see README.md). Put a TLS reverse proxy in front.
FROM python:3.12-slim
RUN pip install --no-cache-dir "cryptography==50.0.2" "gunicorn==23.0.0" \
    && useradd --system --no-create-home provider
COPY wallet_provider.py tpm2.py /app/
WORKDIR /app
USER provider
EXPOSE 8080
# Configured by WP_URL, WP_KEY, WP_CERTS, WP_SECRET (and optional WP_*), read at start.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--access-logfile", "-", \
     "wallet_provider:create_app()"]
