# -*- coding: utf-8 -*-
"""
Log Error Analyzer
==================
读取指定目录下所有 .log 文件，提取并分析错误日志，生成 HTML 分析报告。

用法:
    python analyzer.py [日志目录] [输出文件]
    python analyzer.py sample_logs                    # 分析 sample_logs/ 目录
    python analyzer.py sample_logs my_report          # 分析并输出到 my_report.html
    python analyzer.py --config config.yaml           # 使用配置文件
    python analyzer.py --help                         # 查看完整帮助
"""

import os
import re
import sys
import html
import json
import time
import logging
import argparse
import webbrowser
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ─── 日志配置 ───────────────────────────────────────────────────────────────

logger = logging.getLogger("analyzer")

def setup_logging(verbose: bool = False, quiet: bool = False):
    """配置日志输出级别"""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(handler)
    logger.setLevel(level)

ERROR_KEYWORDS = re.compile(
    r'\b(ERROR|WARN(?:ING)?|Exception|Traceback|FATAL|CRITICAL)\b',
    re.IGNORECASE,
)

# 日志级别优先级（越大越严重）
LEVEL_ORDER = {
    "DEBUG": 0, "INFO": 1, "NOTICE": 2,
    "WARN": 3, "WARNING": 3,
    "ERROR": 4, "CRITICAL": 5, "FATAL": 5,
}

LEVEL_CSS_CLASS = {
    "DEBUG": "level-debug", "INFO": "level-info", "NOTICE": "level-notice",
    "WARN": "level-warn", "WARNING": "level-warn",
    "ERROR": "level-error", "CRITICAL": "level-fatal", "FATAL": "level-fatal",
}

# 指纹提取正则
_VAR_PATTERNS = [
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "{IP}"),
    (re.compile(r":\d{2,5}\b"), ":{PORT}"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\b"), "{TS}"),
    (re.compile(r"\b\d+\.\d+s\b"), "{DUR}s"),
    (re.compile(r"\b\d+ms\b"), "{DUR}ms"),
    (re.compile(r"\bPAY-\d{8}-\d+\b"), "{ORDER}"),
    (re.compile(r"\border #\d+\b"), "order #{N}"),
    (re.compile(r"\buser_id=\d+\b"), "user_id={N}"),
    (re.compile(r"\b/\S+/[\w.]+\.\w+\b"), "/{PATH}"),
]

# ─── 常见日志格式的正则表达式 ──────────────────────────────────────────────

PAT_A = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[([A-Z]+)\]\s+'
    r'([\w.]+)\s*[-:]\s*(.*)',
    re.IGNORECASE,
)

PAT_B = re.compile(
    r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+'
    r'([\w.]+)\s*[-:]\s*(.*)',
    re.IGNORECASE,
)

PAT_C = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})[,.]?\d*\s+'
    r'([A-Z]+)\s+'
    r'([\w.]+)\s*[-:]\s*(.*)',
    re.IGNORECASE,
)

PAT_NGINX = re.compile(
    r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s+[+\-]\d{4}\s+'
    r'([\w]+)\s*[-:]\s*(.*)',
    re.IGNORECASE,
)

# Format D: [2024-01-15 10:23:45] [INFO] [module] message
PAT_D = re.compile(
    r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+'
    r'\[([A-Z]+)\]\s+'
    r'\[([\w.]+)\]\s*(.*)',
    re.IGNORECASE,
)


def _normalize_level(raw: str) -> str:
    upper = raw.upper().strip()
    if upper in ("WARNING",):
        return "WARN"
    if upper in ("CRITICAL",):
        return "FATAL"
    return upper


def _extract_module_from_message(msg: str) -> str | None:
    m = re.search(r'((?:com|org|io|net)\.[\w.]+)', msg)
    if m:
        return m.group(1)
    for kw in ("nginx", "postgresql", "redis", "mysql", "elasticsearch"):
        if kw in msg.lower():
            return kw
    return None


def _parse_line(line: str) -> dict | None:
    stripped = line.strip()
    if not stripped:
        return None

    ts, level, source, message = None, None, None, stripped

    for pat, level_idx, src_idx, msg_idx in (
        (PAT_A, 2, 3, 4),
        (PAT_C, 2, 3, 4),
        (PAT_D, 2, 3, 4),
        (PAT_B, None, 2, 3),
        (PAT_NGINX, None, 2, 3),
    ):
        m = pat.search(stripped)
        if m:
            ts = m.group(1)
            if level_idx:
                level = _normalize_level(m.group(level_idx))
            else:
                km = ERROR_KEYWORDS.search(stripped)
                if km:
                    level = _normalize_level(km.group(1))
                else:
                    level = "INFO"
            source = m.group(src_idx).split(".")[-1]
            message = m.group(msg_idx)
            break

    if level is None:
        km = ERROR_KEYWORDS.search(stripped)
        if km:
            level = _normalize_level(km.group(1))
            source = _extract_module_from_message(stripped) or "unknown"
            message = stripped
        else:
            return None

    hour = None
    if ts:
        try:
            if "/" in ts and ":" in ts:
                dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
            else:
                dt = datetime.strptime(ts.split(",")[0].split(".")[0], "%Y-%m-%d %H:%M:%S")
            hour = dt.hour
        except ValueError:
            hour = None

    return {
        "timestamp": ts or "N/A",
        "hour": hour,
        "level": level,
        "source": source or "unknown",
        "message": message.strip(),
        "raw": stripped,
    }


# ─── 扫描目录 ───────────────────────────────────────────────────────────────


# ─── 指纹与去重 ────────────────────────────────────────────────────────────
def _fingerprint(entry: dict) -> str:
    raw = entry["raw"]
    for pat, repl in _VAR_PATTERNS:
        raw = pat.sub(repl, raw)
    return f"{entry["level"]}|{entry["source"]}|{raw}"

def _deduplicate(entries: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    order = []
    for e in entries:
        fp = _fingerprint(e)
        if fp not in groups:
            groups[fp] = []
            order.append(fp)
        groups[fp].append(e)
    result = []
    for fp in order:
        items = groups[fp]
        merged = dict(items[0])
        merged["_count"] = len(items)
        merged["_first_ts"] = items[0].get("timestamp", "N/A")
        merged["_last_ts"] = items[-1].get("timestamp", "N/A")
        result.append(merged)
    return result



# ─── 配置文件加载 ────────────────────────────────────────────────────────────

def load_config(config_path: str) -> dict:
    """加载 YAML 或 JSON 配置文件"""
    path = Path(config_path)
    if not path.exists():
        logger.debug("配置文件不存在: %s，使用默认配置", config_path)
        return {}

    try:
        content = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            if HAS_YAML:
                config = yaml.safe_load(content) or {}
                logger.info("已加载 YAML 配置: %s", config_path)
                return config
            else:
                logger.warning("未安装 PyYAML，无法加载 YAML 配置。请运行: pip install pyyaml")
                return {}
        elif path.suffix == ".json":
            config = json.loads(content)
            logger.info("已加载 JSON 配置: %s", config_path)
            return config
        else:
            logger.warning("不支持的配置格式: %s", path.suffix)
            return {}
    except Exception as e:
        logger.error("加载配置文件失败: %s", e)
        return {}


DEFAULT_CONFIG = {
    "scan": {
        "log_dir": "logs",
        "pattern": "*.log",
        "exclude": [],
        "max_file_size_mb": 100,
        "encoding": "utf-8",
    },
    "analysis": {
        "levels": ["ERROR", "WARN", "WARNING", "FATAL", "CRITICAL", "Exception", "Traceback"],
        "dedup": True,
        "context_lines": 3,
    },
    "output": {
        "format": "html",
        "dir": "reports",
        "auto_open": True,
        "filename_template": "report_{date}_{time}",
    },
    "alert": {
        "enabled": False,
        "levels": ["FATAL", "CRITICAL"],
        "channels": [],
    },
    "watch": {
        "enabled": False,
        "interval_seconds": 30,
    },
}



# ─── 告警管理器 ──────────────────────────────────────────────────────────────

class AlertManager:
    """告警通知管理器 - 支持钉钉、企业微信、邮件、Bark"""

    def __init__(self, config: dict):
        alert_cfg = config.get("alert", {})
        self.enabled = alert_cfg.get("enabled", False)
        self.alert_levels = alert_cfg.get("levels", ["FATAL", "CRITICAL"])
        self.channels = alert_cfg.get("channels", [])
        self._last_alert_time = {}  # 限流：记录每个渠道上次告警时间
        self._cooldown_seconds = 300  # 同一渠道5分钟内不重复告警

    def should_alert(self, level: str) -> bool:
        """检查该级别是否需要告警"""
        return self.enabled and level in self.alert_levels

    def send_alert(self, data: dict):
        """发送告警到所有配置的渠道"""
        if not self.enabled:
            return

        stats = data["stats"]
        # 检查是否有需要告警的级别
        has_alert_level = False
        for level, count in stats["level_sorted"]:
            if level in self.alert_levels and count > 0:
                has_alert_level = True
                break

        if not has_alert_level:
            return

        message = self._build_message(stats)

        for channel in self.channels:
            channel_type = channel.get("type", "")
            try:
                # 限流检查
                if not self._check_cooldown(channel_type):
                    logger.debug("告警渠道 %s 在冷却期内，跳过", channel_type)
                    continue

                if channel_type == "webhook":
                    self._send_webhook(channel, message)
                elif channel_type == "email":
                    self._send_email(channel, message)
                elif channel_type == "bark":
                    self._send_bark(channel, message)
                else:
                    logger.warning("未知的告警渠道类型: %s", channel_type)

                self._last_alert_time[channel_type] = time.time()
                logger.info("告警已发送到 %s", channel_type)

            except Exception as e:
                logger.error("告警发送失败 [%s]: %s", channel_type, e)

    def _check_cooldown(self, channel_type: str) -> bool:
        """检查渠道是否在冷却期内"""
        last_time = self._last_alert_time.get(channel_type, 0)
        return (time.time() - last_time) >= self._cooldown_seconds

    def _build_message(self, stats: dict) -> str:
        """构建告警消息"""
        lines = []
        lines.append("=== 日志错误告警 ===")
        lines.append("时间: %s" % stats.get("scan_time", "N/A"))
        lines.append("文件数: %d" % stats.get("file_count", 0))
        lines.append("总错误数: %d" % stats.get("total", 0))
        lines.append("")
        lines.append("各级别统计:")
        for level, count in stats.get("level_sorted", []):
            if count > 0:
                lines.append("  %s: %d" % (level, count))

        # TOP 5 错误源
        top_sources = stats.get("top_sources", [])
        if top_sources:
            lines.append("")
            lines.append("TOP 5 错误模块:")
            for source, count in top_sources:
                lines.append("  %s: %d" % (source, count))

        return "\n".join(lines)

    def _send_webhook(self, channel: dict, message: str):
        """发送 Webhook 通知 (钉钉/企业微信)"""
        import urllib.request
        url = channel.get("url", "")
        if not url:
            logger.warning("Webhook URL 为空")
            return

        # 钉钉格式
        payload = json.dumps({
            "msgtype": "text",
            "text": {"content": message}
        })

        req = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=10)

    def _send_email(self, channel: dict, message: str):
        """发送邮件通知"""
        import smtplib
        from email.mime.text import MIMEText

        smtp_host = channel.get("smtp_host", "")
        smtp_port = channel.get("smtp_port", 465)
        username = channel.get("username", "")
        password = channel.get("password", "")
        from_addr = channel.get("from_addr", "")
        to_addrs = channel.get("to_addrs", [])
        use_ssl = channel.get("use_ssl", True)

        if not all([smtp_host, username, password, from_addr, to_addrs]):
            logger.warning("邮件配置不完整")
            return

        msg = MIMEText(message, "plain", "utf-8")
        msg["Subject"] = "日志错误告警 - %s" % datetime.now().strftime("%Y-%m-%d %H:%M")
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)

        if use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)

    def _send_bark(self, channel: dict, message: str):
        """发送 Bark 通知 (iOS)"""
        import urllib.request
        url = channel.get("url", "")
        if not url:
            logger.warning("Bark URL 为空")
            return

        title = "日志错误告警"
        body = message[:500]  # Bark 有长度限制
        bark_url = "%s/%s/%s" % (url.rstrip("/"), title, body)

        req = urllib.request.Request(bark_url, method="GET")
        urllib.request.urlopen(req, timeout=10)




# ─── 历史记录 ────────────────────────────────────────────────────────────────

HISTORY_FILE = "history.json"

def save_history(data: dict, history_file: str = None):
    """保存本次扫描结果到历史记录"""
    if history_file is None:
        history_file = HISTORY_FILE

    stats = data["stats"]
    record = {
        "time": stats.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "total": stats.get("total", 0),
        "file_count": stats.get("file_count", 0),
        "total_lines": stats.get("total_lines", 0),
        "levels": {level: count for level, count in stats.get("level_sorted", [])},
    }

    # 读取现有历史
    history = {"records": []}
    try:
        if Path(history_file).exists():
            with open(history_file, "r", encoding="utf-8") as f:
                history = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("读取历史记录失败: %s，将创建新文件", e)

    # 添加新记录
    history.setdefault("records", []).append(record)

    # 只保留最近 1000 条记录
    if len(history["records"]) > 1000:
        history["records"] = history["records"][-1000:]

    # 保存
    try:
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
        logger.debug("历史记录已保存: %s (%d 条)", history_file, len(history["records"]))
    except FileNotFoundError:
        logger.error("无法保存历史记录: 目录不存在 - %s", history_file)
    except OSError as e:
        logger.error("保存历史记录失败: %s", e)


def load_history(history_file: str = None) -> dict:
    """加载历史记录"""
    if history_file is None:
        history_file = HISTORY_FILE

    try:
        if Path(history_file).exists():
            with open(history_file, "r", encoding="utf-8") as f:
                return json.load(f)
    except FileNotFoundError:
        logger.debug("历史记录文件不存在: %s", history_file)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("加载历史记录失败: %s", e)

    return {"records": []}


def get_trend_data(history: dict, hours: int = 24) -> list[dict]:
    """获取最近N小时的趋势数据"""
    records = history.get("records", [])
    if not records:
        return []

    # 按时间排序
    records = sorted(records, key=lambda x: x.get("time", ""))

    # 返回最近的记录
    return records[-hours:] if len(records) > hours else records

def scan_directory(log_dir: str, config: dict = None) -> dict:
    if config is None:
        config = {}
    scan_cfg = config.get("scan", {})
    max_file_size = scan_cfg.get("max_file_size_mb", 100) * 1024 * 1024
    file_pattern = scan_cfg.get("pattern", "*.log")
    exclude_patterns = scan_cfg.get("exclude", [])
    file_encoding = scan_cfg.get("encoding", "utf-8")

    log_path = Path(log_dir)
    if not log_path.is_dir():
        logger.error("目录不存在: %s", log_dir)
        logger.info("请检查路径是否正确，或使用 --help 查看用法")
        sys.exit(1)

    files_entries: dict[str, list[dict]] = {}
    files_raw: dict[str, list[str]] = {}
    all_entries: list[dict] = []
    total_lines = 0

    # 统计文件数量用于进度显示
    log_files = sorted(log_path.rglob(file_pattern))
    file_count = len(log_files)
    show_progress = file_count > 5 and logger.isEnabledFor(logging.INFO)

    for file_idx, log_file in enumerate(log_files, 1):
        rel = str(log_file.relative_to(log_path))
        entries = []
        raw_lines = []
        file_lines = 0
        # 检查文件大小
        try:
            file_size = log_file.stat().st_size
            if file_size > max_file_size:
                logger.warning("跳过大文件: %s (%.1f MB > %.0f MB 限制)", rel, file_size / 1024 / 1024, max_file_size / 1024 / 1024)
                continue
        except OSError:
            pass

        try:
            with open(log_file, "r", encoding=file_encoding, errors="replace") as f:
                for raw_line in f:
                    file_lines += 1
                    raw_lines.append(raw_line.rstrip())
                    parsed = _parse_line(raw_line)
                    if parsed:
                        parsed["file"] = rel
                        parsed["_line_idx"] = file_lines - 1
                        entries.append(parsed)
        except FileNotFoundError:
            logger.warning("文件不存在: %s", rel)
        except PermissionError:
            logger.warning("没有读取权限: %s", rel)
        except Exception as e:
            logger.warning("读取 %s 失败: %s", rel, e)
        total_lines += file_lines
        files_entries[rel] = entries
        files_raw[rel] = raw_lines
        all_entries.extend(entries)

        # 进度显示
        if show_progress and file_idx % 10 == 0:
            logger.info("扫描进度: %d/%d 文件 (%.0f%%)", file_idx, file_count, file_idx / file_count * 100)

    # 扫描完成
    if show_progress:
        logger.info("扫描进度: %d/%d 文件 (100%%)", file_count, file_count)

    # ── 统计 ──
    level_counts = Counter(e["level"] for e in all_entries)
    source_counts = Counter(e["source"] for e in all_entries)
    file_counts = {k: len(v) for k, v in files_entries.items()}
    hour_counts = defaultdict(int)
    for e in all_entries:
        if e["hour"] is not None:
            hour_counts[e["hour"]] += 1

    top_sources = source_counts.most_common(5)
    level_sorted = sorted(level_counts.items(), key=lambda x: LEVEL_ORDER.get(x[0], 99), reverse=True)

    stats = {
        "total": len(all_entries),
        "total_lines": total_lines,
        "file_count": len(files_entries),
        "level_counts": level_counts,
        "level_sorted": level_sorted,
        "source_counts": source_counts,
        "top_sources": top_sources,
        "file_counts": file_counts,
        "hour_counts": dict(hour_counts),
        "log_dir": str(log_path.resolve()),
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    return {
        "files": files_entries,
        "files_raw": files_raw,
        "all_entries": all_entries,
        "stats": stats,
    }


# ─── HTML 报告生成 ──────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return html.escape(str(s))


def _pie_chart_data(counts: list[tuple[str, int]], colors: dict[str, str]):
    total = sum(c for _, c in counts) or 1
    segments = []
    acc = 0
    for name, count in counts:
        pct = count / total * 100
        color = colors.get(name, "#999")
        segments.append(f"{color} {acc:.2f}% {acc + pct:.2f}%")
        acc += pct
    return f"conic-gradient({', '.join(segments)})"



# ─── 上下文 HTML ────────────────────────────────────────────────────────────
def _build_context_html(entry: dict, raw_lines: list, ctx_radius: int = 3) -> str:
    idx = entry.get("_line_idx", -1)
    if idx < 0 or not raw_lines:
        return ""
    start = max(0, idx - ctx_radius)
    end = min(len(raw_lines), idx + ctx_radius + 1)
    lines_html = []
    for i in range(start, end):
        line_text = html.escape(raw_lines[i])
        if i == idx:
            lines_html.append(f'<div class="ctx-line ctx-error">{line_text}</div>')
        else:
            lines_html.append(f'<div class="ctx-line ctx-normal">{line_text}</div>')
    return chr(10).join(lines_html)



# ─── HTML 辅助函数 ──────────────────────────────────────────────────────────

def _generate_css(pie_bg: str, total: int) -> str:
    """生成 CSS 样式"""
    return f"""
<style>
  :root {{
    --bg: #0f172a; --card: #1e293b; --border: #334155;
    --text: #e2e8f0; --text-dim: #94a3b8; --accent: #38bdf8;
    --input-bg: #1e293b; --hover-bg: rgba(56,189,248,.08);
  }}
  body.light {{
    --bg: #f1f5f9; --card: #ffffff; --border: #e2e8f0;
    --text: #1e293b; --text-dim: #64748b; --accent: #0284c7;
    --input-bg: #ffffff; --hover-bg: rgba(2,132,199,.06);
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg); color: var(--text);
    line-height: 1.6; padding: 24px;
    transition: background .3s, color .3s;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .toolbar {{
    position: sticky; top: 0; z-index: 100;
    display: flex; justify-content: space-between; align-items: center;
    padding: 12px 16px; margin: -24px -24px 16px -24px;
    background: var(--card); border-bottom: 1px solid var(--border);
    backdrop-filter: blur(8px); gap: 12px; flex-wrap: wrap;
    transition: background .3s;
  }}
  body.light .toolbar {{ background: rgba(255,255,255,.92); }}
  body:not(.light) .toolbar {{ background: rgba(30,41,59,.92); }}
  .search-box {{
    display: flex; align-items: center; gap: 8px; flex: 1; max-width: 420px;
  }}
  .search-box input {{
    flex: 1; padding: 8px 14px; border-radius: 8px;
    border: 1px solid var(--border); background: var(--input-bg);
    color: var(--text); font-size: .9rem; outline: none;
    transition: border-color .2s;
  }}
  .search-box input:focus {{ border-color: var(--accent); }}
  .search-box .search-count {{
    font-size: .8rem; color: var(--text-dim); white-space: nowrap; min-width: 70px; text-align: right;
  }}
  .theme-btn {{
    width: 40px; height: 40px; border-radius: 10px; border: 1px solid var(--border);
    background: var(--card); color: var(--text); cursor: pointer;
    font-size: 1.2rem; display: flex; align-items: center; justify-content: center;
    transition: background .2s, transform .15s;
  }}
  .theme-btn:hover {{ background: var(--hover-bg); transform: scale(1.08); }}
  .header {{
    text-align: center; padding: 36px 0 28px;
    border-bottom: 1px solid var(--border); margin-bottom: 32px;
  }}
  .header h1 {{ font-size: 2rem; font-weight: 700; }}
  .header h1 span {{ color: var(--accent); }}
  .overview-bar {{
    display: flex; justify-content: center; gap: 32px; flex-wrap: wrap;
    padding: 16px 0; margin-bottom: 24px;
    border-bottom: 1px solid var(--border);
  }}
  .overview-item {{
    display: flex; align-items: center; gap: 8px; font-size: .9rem; color: var(--text-dim);
  }}
  .overview-item .ov-icon {{ font-size: 1.1rem; }}
  .overview-item .ov-val {{ font-weight: 600; color: var(--text); }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px; text-align: center;
    transition: transform .15s, box-shadow .15s, background .3s;
  }}
  .card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,.25); }}
  .card .num {{ font-size: 2rem; font-weight: 700; }}
  .card .label {{ color: var(--text-dim); font-size: .85rem; margin-top: 4px; }}
  .section {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 28px; margin-bottom: 24px;
    transition: background .3s;
  }}
  .section h2 {{
    font-size: 1.25rem; font-weight: 600; margin-bottom: 20px;
    padding-bottom: 12px; border-bottom: 1px solid var(--border);
  }}
  .section h2::before {{
    content: ''; display: inline-block; width: 4px; height: 20px;
    background: var(--accent); border-radius: 2px;
    margin-right: 10px; vertical-align: middle;
  }}
  .pie-wrap {{ display: flex; align-items: center; gap: 40px; flex-wrap: wrap; }}
  .pie {{
    width: 220px; height: 220px; border-radius: 50%;
    background: {pie_bg};
    position: relative; flex-shrink: 0;
  }}
  .pie::after {{
    content: '{total}'; position: absolute; inset: 36px;
    background: var(--card); border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.6rem; font-weight: 700; color: var(--text);
    transition: background .3s;
  }}
  .legend {{ display: flex; flex-direction: column; gap: 10px; }}
  .legend-item {{ display: flex; align-items: center; gap: 10px; }}
  .legend-dot {{ width: 14px; height: 14px; border-radius: 4px; flex-shrink: 0; }}
  .legend-label {{ flex: 1; }}
  .legend-val {{ font-weight: 600; min-width: 48px; text-align: right; }}
  .bar-list {{ display: flex; flex-direction: column; gap: 12px; }}
  .bar-row {{ display: flex; align-items: center; gap: 12px; }}
  .bar-label {{ width: 160px; text-align: right; font-size: .85rem; color: var(--text-dim);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .bar-track {{ flex: 1; height: 28px; background: var(--bg); border-radius: 6px; overflow: hidden; position: relative; }}
  .bar-fill {{
    height: 100%; border-radius: 6px;
    background: linear-gradient(90deg, var(--accent), #818cf8);
    display: flex; align-items: center; padding-left: 10px;
    font-size: .8rem; font-weight: 600; color: #fff;
    min-width: 36px; transition: width .4s ease;
  }}
  .hour-chart {{ display: flex; align-items: flex-end; gap: 4px; height: 200px; padding: 0 8px; }}
  .hour-col {{
    flex: 1; display: flex; flex-direction: column; align-items: center;
    justify-content: flex-end; height: 100%; position: relative;
  }}
  .hour-bar {{
    width: 100%; max-width: 40px; border-radius: 4px 4px 0 0;
    background: linear-gradient(180deg, var(--accent), #6366f1);
    transition: height .4s ease; min-height: 2px;
  }}
  .hour-bar:hover {{ opacity: .85; }}
  .hour-bar-val {{
    position: absolute; top: -20px; left: 50%; transform: translateX(-50%);
    font-size: .7rem; color: var(--text-dim); white-space: nowrap;
  }}
  .hour-label {{
    margin-top: 6px; font-size: .65rem; color: var(--text-dim);
    writing-mode: vertical-lr; text-orientation: mixed;
  }}
  .file-table {{ width: 100%; border-collapse: collapse; }}
  .file-table th, .file-table td {{
    padding: 10px 16px; text-align: left; border-bottom: 1px solid var(--border);
  }}
  .file-table th {{ color: var(--text-dim); font-weight: 500; font-size: .85rem; }}
  .file-table tr:hover td {{ background: var(--hover-bg); }}
  .filter-bar {{
    display: flex; align-items: center; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;
  }}
  .filter-bar .filter-label {{ font-size: .85rem; color: var(--text-dim); margin-right: 4px; }}
  .filter-btn {{
    padding: 4px 14px; border-radius: 16px; border: 1px solid var(--border);
    background: var(--input-bg); color: var(--text-dim); font-size: .8rem;
    cursor: pointer; transition: all .2s; font-weight: 500;
  }}
  .filter-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
  .filter-btn.active {{
    background: var(--accent); color: #fff; border-color: var(--accent);
  }}
  .count-badge {{
    display: inline-block; padding: 1px 8px; border-radius: 10px;
    font-size: .7rem; font-weight: 600; background: rgba(231,76,60,.25); color: #e74c3c;
    margin-left: 8px;
  }}
  details {{
    margin-bottom: 8px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
    transition: background .3s;
  }}
  details summary {{
    padding: 12px 16px; cursor: pointer; font-weight: 500;
    display: flex; align-items: center; gap: 10px;
    background: var(--hover-bg); transition: background .15s;
  }}
  details summary:hover {{ background: rgba(56,189,248,.12); }}
  details[open] summary {{ border-bottom: 1px solid var(--border); }}
  details .entry {{
    padding: 10px 16px; border-bottom: 1px solid rgba(51,65,85,.3);
    font-size: .85rem; transition: background .2s;
  }}
  body.light details .entry {{ border-bottom-color: #e2e8f0; }}
  details .entry:last-child {{ border-bottom: none; }}
  details .entry:hover {{ background: var(--hover-bg); }}
  details .entry.hidden {{ display: none; }}
  details .entry .ts {{ color: var(--text-dim); margin-right: 8px; }}
  details .entry .src {{ color: var(--accent); margin-right: 8px; }}
  .ctx-wrap {{
    max-height: 0; overflow: hidden; transition: max-height .3s ease;
    background: var(--bg); border-top: 1px solid transparent;
  }}
  details .entry.expanded + .ctx-wrap {{ max-height: 500px; border-top-color: var(--border); }}
  .ctx-line {{
    padding: 2px 16px 2px 32px; font-size: .78rem; font-family: monospace;
    white-space: pre-wrap; word-break: break-all; line-height: 1.5;
  }}
  .ctx-normal {{ color: var(--text-dim); }}
  .ctx-error {{
    color: #e74c3c; background: rgba(231,76,60,.08); font-weight: 500;
    border-left: 3px solid #e74c3c; margin-left: -3px;
  }}
  body.light .ctx-error {{ background: rgba(231,76,60,.06); }}
  .badge {{
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-size: .75rem; font-weight: 600; text-transform: uppercase;
  }}
  .level-error {{ background: rgba(231,76,60,.2); color: #e74c3c; }}
  .level-warn  {{ background: rgba(243,156,18,.2); color: #f39c12; }}
  .level-fatal {{ background: rgba(142,68,173,.2); color: #8e44ad; }}
  .level-info  {{ background: rgba(52,152,219,.15); color: #3498db; }}
  .level-debug {{ background: rgba(149,165,166,.15); color: #95a5a6; }}
  .level-notice {{ background: rgba(46,204,113,.15); color: #2ecc71; }}
  body.light .level-error {{ background: rgba(231,76,60,.12); }}
  body.light .level-warn  {{ background: rgba(243,156,18,.12); }}
  body.light .level-fatal {{ background: rgba(142,68,173,.12); }}
  body.light .level-info  {{ background: rgba(52,152,219,.1); }}
  body.light .level-debug {{ background: rgba(149,165,166,.1); }}
  .no-results {{
    text-align: center; padding: 32px; color: var(--text-dim); font-size: .95rem;
    display: none;
  }}
  .back-top {{
    position: fixed; bottom: 32px; right: 32px; width: 44px; height: 44px;
    border-radius: 50%; border: 1px solid var(--border);
    background: var(--card); color: var(--accent); font-size: 1.2rem;
    cursor: pointer; display: none; align-items: center; justify-content: center;
    box-shadow: 0 4px 16px rgba(0,0,0,.3); transition: all .2s; z-index: 200;
  }}
  .back-top:hover {{ transform: translateY(-2px); background: var(--accent); color: #fff; }}
  .footer {{
    text-align: center; padding: 24px 0; color: var(--text-dim); font-size: .8rem;
    border-top: 1px solid var(--border); margin-top: 32px;
  }}
</style>"""


def _generate_toolbar_html() -> str:
    """生成工具栏 HTML"""
    return """
<div class="toolbar">
  <div class="search-box">
    <input type="text" id="searchInput" placeholder="搜索关键词..." oninput="applyFilters()">
    <span class="search-count" id="searchCount"></span>
  </div>
  <div class="toolbar-right">
    <label class="btn" for="dedupToggle" title="合并相似错误">&#128203; 去重</label>
    <input type="checkbox" id="dedupToggle" style="display:none" onchange="applyFilters()">
    <button class="btn btn-primary" onclick="exportCSV()" title="导出 CSV">&#128229; CSV</button>
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()" title="切换深色/浅色主题">&#9790;</button>
  </div>
</div>"""


def _generate_header_html() -> str:
    """生成页头 HTML"""
    return """
<div class="header">
  <h1>&#128203; <span>日志错误分析报告</span></h1>
</div>"""


def _generate_overview_html(stats: dict) -> str:
    """生成概览栏 HTML"""
    return f"""
<div class="overview-bar">
  <div class="overview-item">
    <span class="ov-icon">&#128336;</span>
    <span>分析时间:</span>
    <span class="ov-val">{_esc(stats['scan_time'])}</span>
  </div>
  <div class="overview-item">
    <span class="ov-icon">&#128196;</span>
    <span>扫描文件:</span>
    <span class="ov-val">{stats['file_count']} 个</span>
  </div>
  <div class="overview-item">
    <span class="ov-icon">&#128209;</span>
    <span>总日志行数:</span>
    <span class="ov-val">{stats['total_lines']:,}</span>
  </div>
  <div class="overview-item">
    <span class="ov-icon">&#9888;&#65039;</span>
    <span>错误/警告:</span>
    <span class="ov-val">{stats['total']} 条</span>
  </div>
</div>"""


def _generate_stats_cards_html(level_sorted: list, total: int, file_count: int, total_lines: int) -> str:
    """生成统计卡片 HTML"""
    parts = ['<div class="cards">']
    for level, count in level_sorted:
        cls = LEVEL_CSS_CLASS.get(level, "level-info")
        parts.append(f'<div class="card"><div class="num"><span class="badge {cls}">{_esc(level)}</span> {count}</div><div class="label">{_esc(level)} 级别</div></div>')
    parts.append(f'<div class="card"><div class="num" style="color:#38bdf8">{total}</div><div class="label">总错误条数</div></div>')
    parts.append(f'<div class="card"><div class="num" style="color:#2ecc71">{file_count}</div><div class="label">扫描文件数</div></div>')
    parts.append(f'<div class="card"><div class="num" style="color:#a78bfa">{total_lines:,}</div><div class="label">总日志行数</div></div>')
    parts.append('</div>')
    return '\n'.join(parts)


def _generate_pie_html(level_sorted: list, total: int, pie_bg: str, level_colors: dict) -> str:
    """生成饼图 HTML"""
    parts = ['<div class="section"><h2>错误级别分布</h2><div class="pie-wrap"><div class="pie"></div><div class="legend">']
    for level, count in level_sorted:
        color = level_colors.get(level, "#999")
        pct = (count / total * 100) if total else 0
        parts.append(f'<div class="legend-item"><div class="legend-dot" style="background:{color}"></div><div class="legend-label">{_esc(level)}</div><div class="legend-val">{count} <span style="color:var(--text-dim)">({pct:.1f}%)</span></div></div>')
    parts.append('</div></div></div>')
    return '\n'.join(parts)


def _generate_top5_html(top_sources: list, top_max: int) -> str:
    """生成 TOP5 柱状图 HTML"""
    parts = ['<div class="section"><h2>错误频率最高的模块 (TOP 5)</h2><div class="bar-list">']
    for label, count in top_sources:
        w = (count / top_max * 100) if top_max else 0
        parts.append(f'<div class="bar-row"><div class="bar-label">{_esc(label)}</div><div class="bar-track"><div class="bar-fill" style="width:{w:.1f}%">{count}</div></div></div>')
    parts.append('</div></div>')
    return '\n'.join(parts)


def _generate_hourly_html(hour_bar_heights: list) -> str:
    """生成时间分布图 HTML"""
    parts = ['<div class="section"><h2>错误时间分布（按小时）</h2><div class="hour-chart">']
    for h, val, h_pct in hour_bar_heights:
        parts.append(f'<div class="hour-col"><div class="hour-bar" style="height:{max(h_pct, 2):.1f}%" title="{h:02d}:00 - {val} 条"></div><div class="hour-bar-val">{val if val else ""}</div><div class="hour-label">{h:02d}</div></div>')
    parts.append('</div></div>')
    return '\n'.join(parts)


def _generate_files_html(file_counts: dict) -> str:
    """生成文件统计表 HTML"""
    parts = ['<div class="section"><h2>各文件错误数量</h2><table class="file-table"><thead><tr><th>文件名</th><th>错误数量</th></tr></thead><tbody>']
    for fname, cnt in sorted(file_counts.items(), key=lambda x: -x[1]):
        parts.append(f'<tr><td>{_esc(fname)}</td><td>{cnt}</td></tr>')
    parts.append('</tbody></table></div>')
    return '\n'.join(parts)


def _generate_errors_html(files: dict, files_raw: dict, all_levels: list) -> str:
    """生成错误详情列表 HTML"""
    parts = ['<div class="section"><h2>详细错误列表</h2>']
    parts.append('<div class="filter-bar"><span class="filter-label">按级别筛选:</span>')
    parts.append('<button class="filter-btn active" data-level="ALL" onclick="filterByLevel(this)">全部</button>')
    for lv in all_levels:
        parts.append(f'<button class="filter-btn" data-level="{_esc(lv)}" onclick="filterByLevel(this)">{_esc(lv)}</button>')
    parts.append('</div>')
    parts.append('<div id="noResults" class="no-results">&#128269; 没有匹配的错误记录</div>')

    for fname, file_entries in files.items():
        if not file_entries:
            continue
        raw_lines = files_raw.get(fname, [])
        deduped = _deduplicate(file_entries)
        sorted_entries = sorted(deduped, key=lambda e: LEVEL_ORDER.get(e["level"], 99), reverse=True)
        file_summary_level = sorted_entries[0]["level"]
        orig_count = len(file_entries)
        dedup_count = len(sorted_entries)

        parts.append(f'<details open><summary><span class="badge {LEVEL_CSS_CLASS.get(file_summary_level, "level-info")}">{_esc(file_summary_level)}</span> {_esc(fname)} &nbsp;({orig_count} 条{"" if orig_count == dedup_count else f", 去重后 {dedup_count} 条"})</summary>')

        for entry in sorted_entries:
            badge_cls = LEVEL_CSS_CLASS.get(entry["level"], "level-info")
            count_val = entry.get("_count", 1)
            count_html = f' <span class="count-badge">x{count_val}</span>' if count_val > 1 else ""
            ctx_html = _build_context_html(entry, raw_lines)
            parts.append(f'<div class="entry" data-level="{_esc(entry["level"])}" data-text="{_esc(entry["raw"].lower())}" data-count="{count_val}" data-msg="{_esc(entry["message"][:200])}" onclick="toggleContext(this)"><span class="ts">{_esc(entry["timestamp"])}</span><span class="badge {badge_cls}">{_esc(entry["level"])}</span><span class="src">{_esc(entry["source"])}</span>{_esc(entry["message"])}{count_html}</div>')
            if ctx_html:
                parts.append(f'<div class="ctx-wrap">{ctx_html}</div>')
        parts.append('</details>')

    parts.append('</div>')
    return '\n'.join(parts)


def _generate_js_html() -> str:
    """生成 JavaScript HTML"""
    return """
<script>
(function() {
  var entries = document.querySelectorAll('.entry');
  var details = document.querySelectorAll('details');
  var noResults = document.getElementById('noResults');
  var searchInput = document.getElementById('searchInput');
  var searchCount = document.getElementById('searchCount');
  var activeLevel = 'ALL';

  window.toggleContext = function(el) {
    el.classList.toggle('expanded');
    var wrap = el.nextElementSibling;
    if (wrap && wrap.classList.contains('ctx-wrap')) {
      wrap.style.maxHeight = el.classList.contains('expanded') ? wrap.scrollHeight + 'px' : '0';
    }
  };

  function applyFilters() {
    var keyword = searchInput.value.trim().toLowerCase();
    var visible = 0;
    entries.forEach(function(e) {
      var matchLevel = (activeLevel === 'ALL') || (e.dataset.level === activeLevel);
      var textContent = (e.dataset.text + ' ' + (e.dataset.msg || '') + ' ' + e.textContent).toLowerCase();
      var matchSearch = !keyword || textContent.includes(keyword);
      if (matchLevel && matchSearch) {
        e.classList.remove('hidden');
        visible++;
      } else {
        e.classList.add('hidden');
        e.classList.remove('expanded');
        var w = e.nextElementSibling;
        if (w && w.classList.contains('ctx-wrap')) w.style.maxHeight = '0';
      }
    });
    details.forEach(function(d) {
      var hasVisible = d.querySelector('.entry:not(.hidden)');
      d.open = !!hasVisible;
    });
    noResults.style.display = visible === 0 ? 'block' : 'none';
    searchCount.textContent = visible + ' / ' + entries.length + ' 条';
  }
  window.applyFilters = applyFilters;
  window.filterByLevel = function(btn) {
    document.querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    activeLevel = btn.dataset.level;
    applyFilters();
  };
  window.exportCSV = function() {
    var rows = [];
    rows.push(['时间', '级别', '模块', '消息', '文件', '重复次数']);
    var kw = searchInput.value.trim().toLowerCase();
    entries.forEach(function(e) {
      if (e.classList.contains('hidden')) return;
      if (activeLevel !== 'ALL' && e.dataset.level !== activeLevel) return;
      if (kw) {
        var txt = (e.dataset.text + ' ' + (e.dataset.msg || '') + ' ' + e.textContent).toLowerCase();
        if (!txt.includes(kw)) return;
      }
      var ts = e.querySelector('.ts') ? e.querySelector('.ts').textContent.trim() : '';
      var lv = e.dataset.level || '';
      var src = e.querySelector('.src') ? e.querySelector('.src').textContent.trim() : '';
      var msg = e.dataset.msg || '';
      var file = '';
      var det = e.closest('details');
      if (det) {
        var sum = det.querySelector('summary');
        if (sum) {
          var txt = sum.textContent;
          var idx = txt.lastIndexOf('.');
          if (idx > 0) {
            var start = txt.lastIndexOf(' ', idx);
            file = txt.substring(start+1, idx+4);
          }
        }
      }
      var cnt = e.dataset.count || '1';
      rows.push([ts, lv, src, msg, file, cnt]);
    });
    var csv = rows.map(function(r) {
      return r.map(function(c) {
        var s = String(c).replace(/"/g, '""');
        return '"' + s + '"';
      }).join(',');
    }).join('\n');
    var blob = new Blob(['\uFEFF' + csv], {type: 'text/csv;charset=utf-8'});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'log_errors_' + new Date().toISOString().slice(0,10) + '.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };
  searchCount.textContent = entries.length + ' / ' + entries.length + ' 条';
})();
</script>
<script>
(function() {
  var btn = document.getElementById('themeBtn');
  var saved = localStorage.getItem('theme');
  if (saved === 'light') {
    document.body.classList.add('light');
    btn.textContent = '\u2600';
  }
  window.toggleTheme = function() {
    document.body.classList.toggle('light');
    var isLight = document.body.classList.contains('light');
    btn.textContent = isLight ? '\u2600' : '\u263E';
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
  };
})();
</script>
<button class="back-top" id="backTop" onclick="window.scrollTo({top:0,behavior:'smooth'})" title="回到顶部">&#9650;</button>
<script>
(function() {
  var btn = document.getElementById('backTop');
  window.addEventListener('scroll', function() {
    btn.style.display = window.scrollY > 400 ? 'flex' : 'none';
  });
})();
</script>"""


def generate_html(data: dict) -> str:
    """生成 HTML 分析报告"""
    stats = data["stats"]
    files = data["files"]
    files_raw = data.get("files_raw", {})
    entries = data["all_entries"]

    total = stats["total"]
    total_lines = stats["total_lines"]
    file_count = stats["file_count"]
    level_sorted = stats["level_sorted"]
    top_sources = stats["top_sources"]
    file_counts = stats["file_counts"]
    hour_counts = stats["hour_counts"]

    LEVEL_COLORS = {
        "ERROR": "#e74c3c", "WARN": "#f39c12", "WARNING": "#f39c12",
        "FATAL": "#8e44ad", "CRITICAL": "#8e44ad",
        "INFO": "#3498db", "DEBUG": "#95a5a6", "NOTICE": "#2ecc71",
    }

    pie_bg = _pie_chart_data([(l, c) for l, c in level_sorted], LEVEL_COLORS)

    hours = sorted(hour_counts.keys()) if hour_counts else list(range(24))
    hour_max = max(hour_counts.values()) if hour_counts else 1
    hour_bar_heights = []
    for h in hours:
        val = hour_counts.get(h, 0)
        hour_bar_heights.append((h, val, (val / hour_max * 100) if hour_max else 0))

    top_max = top_sources[0][1] if top_sources else 1

    all_levels = sorted(set(e["level"] for e in entries), key=lambda x: LEVEL_ORDER.get(x, 99), reverse=True)

    # 使用辅助函数构建 HTML
    parts = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="zh-CN"><head>')
    parts.append('<meta charset="UTF-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    parts.append('<title>日志错误分析报告</title>')
    parts.append(_generate_css(pie_bg, total))
    parts.append("</head><body><div class='container'>")
    parts.append(_generate_toolbar_html())
    parts.append(_generate_header_html())
    parts.append(_generate_overview_html(stats))
    parts.append(_generate_stats_cards_html(level_sorted, total, file_count, total_lines))
    parts.append(_generate_pie_html(level_sorted, total, pie_bg, LEVEL_COLORS))
    parts.append(_generate_top5_html(top_sources, top_max))
    parts.append(_generate_hourly_html(hour_bar_heights))
    parts.append(_generate_files_html(file_counts))
    parts.append(_generate_errors_html(files, files_raw, all_levels))
    parts.append(_generate_js_html())
    parts.append(f'<div class="footer">Log Error Analyzer &mdash; 纯 Python 实现 &mdash; 生成于 {stats["scan_time"]}</div>')
    parts.append("</div></body></html>")

    return "\n".join(parts)



def generate_json(data: dict) -> str:
    """生成 JSON 格式的分析报告"""
    stats = data["stats"]
    files = data["files"]

    # 构建报告结构
    report = {
        "meta": {
            "scan_time": stats.get("scan_time", ""),
            "log_dir": stats.get("log_dir", ""),
            "total_errors": stats.get("total", 0),
            "total_lines": stats.get("total_lines", 0),
            "file_count": stats.get("file_count", 0),
        },
        "level_summary": {
            level: count for level, count in stats.get("level_sorted", [])
        },
        "top_sources": [
            {"source": src, "count": cnt}
            for src, cnt in stats.get("top_sources", [])
        ],
        "hourly_distribution": stats.get("hour_counts", {}),
        "files": {},
        "errors": [],
    }

    # 按文件统计
    for fname, entries in files.items():
        report["files"][fname] = {
            "total": len(entries),
            "levels": {},
        }
        for entry in entries:
            level = entry.get("level", "UNKNOWN")
            report["files"][fname]["levels"][level] =                 report["files"][fname]["levels"].get(level, 0) + 1

    # 错误详情
    for fname, entries in files.items():
        for entry in entries:
            report["errors"].append({
                "file": fname,
                "timestamp": entry.get("timestamp", ""),
                "level": entry.get("level", ""),
                "source": entry.get("source", ""),
                "message": entry.get("message", ""),
                "raw": entry.get("raw", ""),
            })

    return json.dumps(report, indent=2, ensure_ascii=False)

# ─── 入口 ───────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description="日志错误分析工具 - 扫描日志文件，生成错误分析报告",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s sample_logs                    分析 sample_logs 目录
  %(prog)s /var/log/myapp -o report.html  指定输出文件
  %(prog)s --config config.yaml           使用配置文件
  %(prog)s --watch 30                     每30秒监控一次
  %(prog)s --verbose sample_logs          显示详细信息
        """,
    )
    parser.add_argument(
        "log_dir",
        nargs="?",
        default=None,
        help="日志文件所在目录 (默认: 从配置文件读取，或 ./logs)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="输出报告文件路径 (默认: 自动生成)",
    )
    parser.add_argument(
        "-c", "--config",
        default=None,
        help="配置文件路径 (YAML 或 JSON)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="显示详细扫描信息",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="静默模式，只输出警告和错误",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="不自动打开浏览器",
    )
    parser.add_argument(
        "--dedup",
        action="store_true",
        default=None,
        help="启用错误去重",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=None,
        help="上下文行数 (默认: 3)",
    )
    parser.add_argument(
        "--watch",
        type=int,
        default=None,
        metavar="SECONDS",
        help="监控模式，每N秒扫描一次",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0",
    )
    return parser


def run_analysis(log_dir: str, output: str = None, config: dict = None,
                 no_open: bool = False) -> str:
    """执行一次分析，返回输出文件路径"""
    if config is None:
        config = {}

    logger.info("扫描目录: %s", log_dir)
    data = scan_directory(log_dir, config)

    stats = data["stats"]
    total = stats["total"]
    total_lines = stats["total_lines"]
    file_count = stats["file_count"]
    logger.info("扫描完成: %d 个文件, %d 行日志, %d 条错误/警告", file_count, total_lines, total)

    if total == 0:
        logger.info("未发现错误记录，跳过报告生成。")
        return ""

    for level, count in stats["level_sorted"]:
        logger.info("  %s: %d", level, count)

    # 根据配置选择输出格式
    output_format = config.get("output", {}).get("format", "html")

    if output_format == "json":
        report_content = generate_json(data)
        default_ext = ".json"
    else:
        report_content = generate_html(data)
        default_ext = ".html"

    if output is None:
        output_cfg = config.get("output", {})
        report_dir = Path(output_cfg.get("dir", "reports"))
        report_dir.mkdir(exist_ok=True)
        template = output_cfg.get("filename_template", "report_{date}_{time}")
        now = datetime.now()
        filename = template.replace("{date}", now.strftime("%Y%m%d")).replace("{time}", now.strftime("%H%M%S"))
        if not filename.endswith(".html"):
            filename += ".html"
        output = str(report_dir / filename)
    elif not output.endswith((".html", ".json")):
        output += default_ext

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(output, "w", encoding="utf-8") as f:
            f.write(report_content)
    except FileNotFoundError:
        logger.error("输出目录不存在: %s", Path(output).parent)
        sys.exit(1)
    except PermissionError:
        logger.error("没有写入权限: %s", output)
        sys.exit(1)
    except OSError as e:
        logger.error("写入文件失败: %s", e)
        sys.exit(1)

    logger.info("报告已生成: %s", output)

    # 保存历史记录
    save_history(data)

    if not no_open and output_format != "json":
        abs_path = Path(output).resolve()
        file_url = abs_path.as_uri()
        try:
            webbrowser.open(file_url)
            logger.info("已在浏览器中打开报告")
        except Exception:
            logger.info("无法自动打开浏览器，请手动打开: %s", file_url)

    return output


def watch_mode(log_dir: str, output: str, config: dict, interval: int, no_open: bool):
    """监控模式：定时扫描日志目录"""
    logger.info("进入监控模式，每 %d 秒扫描一次 (Ctrl+C 停止)", interval)
    last_total = None

    # 初始化告警管理器
    alert_mgr = AlertManager(config)

    while True:
        try:
            data = scan_directory(log_dir, config)
            current_total = data["stats"]["total"]

            if last_total is not None and current_total > last_total:
                new_errors = current_total - last_total
                logger.warning("检测到 %d 条新错误！", new_errors)

                # 发送告警通知
                alert_mgr.send_alert(data)

                # 生成新报告
                now = datetime.now()
                watch_output = output.replace(".html", f"_{now.strftime('%H%M%S')}.html")
                run_analysis(log_dir, watch_output, config, no_open=True)

            last_total = current_total
            logger.debug("扫描完成，当前错误总数: %d，等待 %d 秒...", current_total, interval)
            time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("监控已停止")
            break
        except Exception as e:
            logger.error("扫描异常: %s", e)
            time.sleep(interval)


def main():
    parser = build_parser()
    args = parser.parse_args()

    # 配置日志
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    # 加载配置
    config = {}
    if args.config:
        config = load_config(args.config)
    else:
        # 尝试加载默认配置文件
        for default_name in ["config.yaml", "config.yml", "config.json"]:
            if Path(default_name).exists():
                config = load_config(default_name)
                break

    # 合并默认配置
    merged_config = DEFAULT_CONFIG.copy()
    for section, values in config.items():
        if isinstance(values, dict) and section in merged_config:
            merged_config[section].update(values)
        else:
            merged_config[section] = values

    # 确定日志目录
    log_dir = args.log_dir or merged_config.get("scan", {}).get("log_dir", "logs")
    output = args.output
    no_open = args.no_open or not merged_config.get("output", {}).get("auto_open", True)

    # 覆盖配置中的选项
    if args.dedup is not None:
        merged_config.setdefault("analysis", {})["dedup"] = args.dedup
    if args.context is not None:
        merged_config.setdefault("analysis", {})["context_lines"] = args.context

    # 监控模式
    watch_interval = args.watch or (merged_config.get("watch", {}).get("interval_seconds") if merged_config.get("watch", {}).get("enabled") else None)
    if watch_interval:
        watch_output = output or "reports/watch_report.html"
        watch_mode(log_dir, watch_output, merged_config, watch_interval, no_open)
    else:
        run_analysis(log_dir, output, merged_config, no_open)


if __name__ == "__main__":
    main()
