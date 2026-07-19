FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency installation
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml README.md ./
COPY vmware_harden/ vmware_harden/
COPY examples/ examples/

# Install dependencies
RUN uv pip install --system --no-cache .

# Config / DuckDB directory (mount at runtime)
RUN mkdir -p /root/.vmware-harden

# MCP server uses stdio transport — no port needed
CMD ["python", "-m", "vmware_harden.mcp_server"]
