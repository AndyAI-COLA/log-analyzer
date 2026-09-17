# 日志错误分析工具 (Log Error Analyzer)

纯 Python 实现的日志错误分析工具，扫描 .log 文件并生成美观的 HTML 分析报告。

## 功能特性

| 功能 | 说明 |
|------|------|
| 自动扫描 | 读取指定目录下所有 .log 文件（含子目录） |
| 关键字提取 | ERROR, WARN, WARNING, Exception, Traceback, FATAL, CRITICAL |
| 多维分类 | 按级别 / 模块来源 / 时间（小时）分类统计 |
| 错误去重 | 自动合并相似错误，显示重复次数 |
| 上下文展示 | 点击错误行展开前后各 3 行日志上下文 |
| 可视化报告 | 纯 CSS 饼图、柱状图、折线图，零外部依赖 |
| 搜索筛选 | 实时关键词搜索 + 按级别筛选 |
| 主题切换 | 深色/浅色主题，记住用户选择 |
| CSV 导出 | 一键导出分析数据到 CSV |
| JSON 导出 | 结构化 JSON 输出，便于程序集成 |
| 告警通知 | 支持钉钉/企业微信/邮件/Bark 通知 |
| 历史追踪 | 自动记录扫描结果，支持趋势分析 |
| 监控模式 | --watch 参数定时扫描，持续监控 |
| Docker 支持 | 一键容器化部署 |
| CI/CD | GitHub Actions 自动测试 |

## 快速开始

`ash
# 基本用法
python analyzer.py sample_logs

# 指定输出文件
python analyzer.py sample_logs my_report.html

# 使用配置文件
python analyzer.py --config config.yaml

# 监控模式（每30秒扫描一次）
python analyzer.py --watch 30

# JSON 输出
python analyzer.py sample_logs -o report.json
`

## 命令行参数

`
用法: analyzer [-h] [-o OUTPUT] [-c CONFIG] [-v] [-q] [--no-open]
               [--dedup] [--context CONTEXT] [--watch SECONDS] [--version]
               [log_dir]

位置参数:
  log_dir                 日志文件所在目录 (默认: ./logs)

可选参数:
  -h, --help              显示帮助信息
  -o, --output FILE       输出报告文件路径
  -c, --config FILE       配置文件路径 (YAML 或 JSON)
  -v, --verbose           显示详细扫描信息
  -q, --quiet             静默模式，只输出警告和错误
  --no-open               不自动打开浏览器
  --dedup                 启用错误去重
  --context N             上下文行数 (默认: 3)
  --watch SECONDS         监控模式，每N秒扫描一次
  --version               显示版本号
`

## 配置文件

支持 YAML 或 JSON 格式的配置文件：

`yaml
scan:
  log_dir: ./logs
  pattern: "*.log"
  max_file_size_mb: 100

analysis:
  dedup: true
  context_lines: 3

output:
  format: html
  dir: reports
  auto_open: true

alert:
  enabled: false
  levels: ["FATAL", "CRITICAL"]
  channels:
    - type: webhook
      url: https://oapi.dingtalk.com/robot/send?access_token=xxx
    - type: email
      smtp_host: smtp.example.com
      smtp_port: 465
      username: ""
      password: ""
      from_addr: "alert@example.com"
      to_addrs: ["admin@example.com"]

watch:
  enabled: false
  interval_seconds: 30
`

## Docker 部署

`ash
# 构建镜像
docker build -t log-analyzer .

# 运行分析
docker run --rm -v /var/log/myapp:/logs:ro log-analyzer /logs

# 监控模式
docker run --rm -d \
  --name log-monitor \
  -v /var/log/myapp:/logs:ro \
  -v C:\kelecoding\log-analyzer/reports:/reports \
  log-analyzer --watch 60 /logs

# 使用 Docker Compose
docker-compose up                    # 单次分析
docker-compose up -d monitor         # 后台监控
docker-compose down                  # 停止
`

## CI/CD

项目包含 GitHub Actions 配置，push 代码自动测试：

- 测试 Python 3.10/3.11/3.12
- 构建 Docker 镜像
- 运行完整测试套件

## 项目结构

`
log-analyzer/
├── analyzer.py           # 主程序
├── config.yaml           # 配置文件
├── Dockerfile            # Docker 构建
├── docker-compose.yml    # Docker Compose
├── Makefile              # 常用命令
├── requirements.txt      # 依赖说明
├── README.md
├── .github/workflows/
│   └── ci.yml            # CI/CD 配置
├── tests/
│   ├── run_tests.py      # 测试运行器
│   └── test_analyzer.py  # pytest 测试
├── sample_logs/
│   ├── app.log
│   └── server.log
└── reports/
`

## 运行测试

`ash
# 使用内置测试运行器
python tests/run_tests.py

# 使用 Makefile
make test

# 使用 pytest（需安装）
pip install pytest
pytest tests/ -v
`

## 依赖

- **Python 3.10+**
- **零外部依赖**（纯标准库实现）
- **可选**: PyYAML（用于 YAML 配置文件支持）

## License

MIT