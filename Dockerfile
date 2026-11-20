FROM python:3.12-slim
WORKDIR /app
RUN useradd -m -r mcpuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY proxy_core.py mcp_adapter.py ./
USER mcpuser
EXPOSE 10000
CMD ["python", "mcp_adapter.py"]
