FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency installation
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml README.md ./
COPY vmware_harden/ vmware_harden/
COPY examples/ examples/

# Install with the collectors extra: `scan` reads the estate through the
# sibling skills it carries, and an image without them cannot scan anything.
RUN uv pip install --system --no-cache ".[collectors]"

# Config / DuckDB directory (mount at runtime)
RUN mkdir -p /root/.vmware-harden

# MCP server uses stdio transport — no port needed
CMD ["python", "-m", "vmware_harden.mcp_server"]
