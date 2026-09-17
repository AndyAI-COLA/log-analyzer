# ============================================================
# Log Error Analyzer - Dockerfile
# ============================================================
# 用法:
#   docker build -t log-analyzer .
#   docker run --rm -v /var/log/myapp:/logs log-analyzer
#   docker run --rm -v /var/log/myapp:/logs log-analyzer --watch 30
# ============================================================

FROM python:3.12-slim

# 设置工作目录
WORKDIR /app

# 复制依赖文件（利用 Docker 缓存）
COPY requirements.txt .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt || true

# 复制应用代码
COPY analyzer.py .
COPY config.yaml .

# 创建必要的目录
RUN mkdir -p /logs /reports

# 设置非 root 用户运行
RUN useradd -m -u 1000 analyzer && \
    chown -R analyzer:analyzer /app /logs /reports
USER analyzer

# 健康检查
HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# 入口点
ENTRYPOINT ["python", "analyzer.py", "--no-open"]
CMD ["/logs"]