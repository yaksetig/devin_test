FROM python:3.12-slim

# Install system dependencies including Rust (needed for circomspect)
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:/usr/local/bin:${PATH}"

# Install circomspect directly from GitHub
RUN git clone https://github.com/trailofbits/circomspect.git /tmp/circomspect && \
    cd /tmp/circomspect && \
    cargo build --release && \
    cp /tmp/circomspect/target/release/circomspect /usr/local/bin/ && \
    chmod +x /usr/local/bin/circomspect && \
    circomspect --version

# Set up poetry
RUN pip install poetry

WORKDIR /app

# Copy poetry configuration files
COPY pyproject.toml poetry.lock ./

# Configure poetry to not create a virtual environment
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --no-interaction --no-ansi

# Copy application code
COPY . .

# Command to run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
