# Dockerfile - single container for FastAPI backend + fuzzer sources
FROM python:3.11-bullseye

# Build argument for extra libraries with default empty value
ARG EXTRA_LIBS=""

# --- system deps (add packages if your fuzzer needs build tools) ---
RUN set -eux; \
    echo "Extra libs to install: '${EXTRA_LIBS}'"; \
    # enable i386 multiarch if any :i386 package requested
    if printf '%s' "${EXTRA_LIBS}" | grep -q ':i386'; then \
        dpkg --add-architecture i386; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends build-essential ca-certificates file ncurses-term ${EXTRA_LIBS}; \
    rm -rf /var/lib/apt/lists/*

# Set working dir
WORKDIR /app

# Copy requirements and install
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the project
COPY . /app

# Ensure uploads directory exists (the FastAPI backend uses web/back/uploads)
RUN mkdir -p /app/web/back/uploads && chmod 0777 /app/web/back/uploads

# Expose port used by uvicorn
EXPOSE 8000

# Default env -- can be overridden at runtime
# Default template: call src/main.py with target and config placeholders.
ENV FUZZER_CMD_TEMPLATE="python3 /app/src/main.py --mode binary --binary {target} --config {config}"
ENV TERM=xterm-256color

# Run uvicorn (back.py is the FastAPI app in web/back/back.py)
# We run as root in container by default; if you want another user create it and chown files.
CMD ["uvicorn", "web.back.back:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]

