FROM node:20-slim AS base

# Install Python for tokenizer bridge
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python dependencies
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
RUN pip install --no-cache-dir transformers torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir onnxruntime

# Node dependencies
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Application code
COPY dist/ ./dist/
COPY ml/scripts/tokenize_server.py ./ml/scripts/
COPY ml/models/onnx/ ./ml/models/onnx/

ENV PORT=8080
ENV NODE_ENV=production

EXPOSE 8080

CMD ["node", "dist/api-server.js"]
