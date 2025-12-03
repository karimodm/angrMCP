# Use a Python image with uv pre-installed
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

# Install the project into `/app`
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Copy project files needed for dependency installation
COPY pyproject.toml /app/

# Install the project's dependencies using pyproject.toml
# Note: angr-mcp doesn't use a lockfile yet, so we skip --frozen
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv /app/.venv && \
    uv pip install --python /app/.venv/bin/python claripy angr mcp

# Then, add the rest of the project source code and install it
# Installing separately from its dependencies allows optimal layer caching
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --python /app/.venv/bin/python mcpo .

# Final stage - runtime image
FROM python:3.13-slim-bookworm

WORKDIR /app

# Copy the virtual environment from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app /app

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

# Expose port 80 for mcpo server
EXPOSE 80

# Run the angr MCP server via mcpo on port 80 with SSE transport
ENTRYPOINT ["mcpo", "--port", "80", "--", "python", "-m", "angr_mcp", "--transport", "stdio"]
CMD []
