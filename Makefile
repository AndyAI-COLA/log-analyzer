# ============================================================
# Log Error Analyzer - Makefile
# ============================================================
# 用法: make [命令]
# ============================================================

.PHONY: help test run run-verbose run-json clean docker docker-up docker-down

# 默认目标
help:
	@echo "Log Error Analyzer - 可用命令:"
	@echo ""
	@echo "  make test          运行测试"
	@echo "  make run           分析 sample_logs"
	@echo "  make run-verbose   分析 sample_logs (详细输出)"
	@echo "  make run-json      分析并输出 JSON"
	@echo "  make clean         清理临时文件"
	@echo "  make docker        构建 Docker 镜像"
	@echo "  make docker-up     启动 Docker 服务"
	@echo "  make docker-down   停止 Docker 服务"
	@echo "  make monitor       启动监控模式 (30秒间隔)"
	@echo ""

# 运行测试
test:
	python tests/run_tests.py

# 分析示例日志
run:
	python analyzer.py sample_logs --no-open

# 详细输出
run-verbose:
	python analyzer.py sample_logs --no-open --verbose

# JSON 输出
run-json:
	python analyzer.py sample_logs --no-open -o reports/report.json

# 监控模式
monitor:
	python analyzer.py sample_logs --no-open --watch 30

# 清理
clean:
	-rm -rf __pycache__ tests/__pycache__
	-rm -f *.pyc
	-rm -f history.json
	-rm -f reports/*.html reports/*.json

# Docker
docker:
	docker build -t log-analyzer .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

# 安装依赖
install:
	pip install pyyaml pytest