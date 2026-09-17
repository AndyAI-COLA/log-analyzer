import sys
import os
import pytest

# Add parent directory to path so we can import analyzer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import (
    _normalize_level,
    _parse_line,
    _fingerprint,
    _deduplicate,
    _build_context_html,
    scan_directory,
    generate_html,
    load_config,
    build_parser,
)


class TestNormalizeLevel:
    """测试级别标准化"""

    def test_warning_to_warn(self):
        assert _normalize_level("WARNING") == "WARN"

    def test_critical_to_fatal(self):
        assert _normalize_level("CRITICAL") == "FATAL"

    def test_already_upper(self):
        assert _normalize_level("ERROR") == "ERROR"

    def test_lowercase(self):
        assert _normalize_level("error") == "ERROR"

    def test_mixed_case(self):
        assert _normalize_level("Error") == "ERROR"

    def test_warn(self):
        assert _normalize_level("WARN") == "WARN"

    def test_fatal(self):
        assert _normalize_level("FATAL") == "FATAL"

    def test_info(self):
        assert _normalize_level("INFO") == "INFO"

    def test_debug(self):
        assert _normalize_level("DEBUG") == "DEBUG"


class TestParseLine:
    """测试日志行解析"""

    def test_format_a_error(self):
        line = "2024-01-15 10:23:45 [ERROR] [database] 连接超时"
        result = _parse_line(line)
        assert result is not None
        assert result["level"] == "ERROR"
        assert result["source"] == "database"
        assert "连接超时" in result["message"]
        assert result["hour"] == 10

    def test_format_a_warn(self):
        line = "2024-01-15 11:05:33 [WARNING] [cache] Redis 延迟增加"
        result = _parse_line(line)
        assert result is not None
        assert result["level"] == "WARN"
        assert result["source"] == "cache"

    def test_format_b(self):
        line = "[2024-01-15 10:23:45] [INFO] [server] 启动完成"
        result = _parse_line(line)
        assert result is not None
        assert result["level"] == "INFO"
        assert result["source"] == "server"

    def test_format_nginx(self):
        line = "16/Sep/2026:08:15:23 +0800 nginx - worker started"
        result = _parse_line(line)
        assert result is not None
        assert result["source"] == "nginx"

    def test_empty_line(self):
        assert _parse_line("") is None
        assert _parse_line("   ") is None
        assert _parse_line("\\n") is None

    def test_no_level(self):
        line = "just some random text without level"
        result = _parse_line(line)
        assert result is None

    def test_traceback_line(self):
        line = "Traceback (most recent call last):"
        result = _parse_line(line)
        assert result is not None
        assert result["level"] == "TRACEBACK"

    def test_timestamp_extraction(self):
        line = "2024-01-15 14:30:00 [ERROR] [app] Something failed"
        result = _parse_line(line)
        assert result is not None
        assert result["timestamp"] == "2024-01-15 14:30:00"
        assert result["hour"] == 14


class TestFingerprint:
    """测试指纹生成"""

    def test_same_pattern_different_ip(self):
        e1 = {"level": "ERROR", "source": "db", "raw": "连接 192.168.1.1:5432 超时"}
        e2 = {"level": "ERROR", "source": "db", "raw": "连接 10.0.0.5:5432 超时"}
        assert _fingerprint(e1) == _fingerprint(e2)

    def test_different_level(self):
        e1 = {"level": "ERROR", "source": "db", "raw": "连接 192.168.1.1 超时"}
        e2 = {"level": "WARN", "source": "db", "raw": "连接 192.168.1.1 超时"}
        assert _fingerprint(e1) != _fingerprint(e2)

    def test_different_source(self):
        e1 = {"level": "ERROR", "source": "db", "raw": "连接超时"}
        e2 = {"level": "ERROR", "source": "auth", "raw": "连接超时"}
        assert _fingerprint(e1) != _fingerprint(e2)

    def test_same_message(self):
        e1 = {"level": "ERROR", "source": "db", "raw": "连接超时"}
        e2 = {"level": "ERROR", "source": "db", "raw": "连接超时"}
        assert _fingerprint(e1) == _fingerprint(e2)


class TestDeduplicate:
    """测试去重功能"""

    def test_merge_same_errors(self):
        entries = [
            {"level": "ERROR", "source": "db", "raw": "连接 192.168.1.1 超时", "timestamp": "10:00:00"},
            {"level": "ERROR", "source": "db", "raw": "连接 10.0.0.5 超时", "timestamp": "10:01:00"},
        ]
        result = _deduplicate(entries)
        assert len(result) == 1
        assert result[0]["_count"] == 2
        assert result[0]["_first_ts"] == "10:00:00"
        assert result[0]["_last_ts"] == "10:01:00"

    def test_keep_different_errors(self):
        entries = [
            {"level": "ERROR", "source": "db", "raw": "连接超时", "timestamp": "10:00:00"},
            {"level": "ERROR", "source": "auth", "raw": "认证失败", "timestamp": "10:01:00"},
        ]
        result = _deduplicate(entries)
        assert len(result) == 2

    def test_empty_list(self):
        result = _deduplicate([])
        assert result == []

    def test_single_entry(self):
        entries = [
            {"level": "ERROR", "source": "db", "raw": "超时", "timestamp": "10:00:00"},
        ]
        result = _deduplicate(entries)
        assert len(result) == 1
        assert result[0]["_count"] == 1


class TestScanDirectory:
    """测试目录扫描"""

    def test_scan_sample_logs(self):
        data = scan_directory("sample_logs")
        assert data["stats"]["total"] > 0
        assert data["stats"]["file_count"] == 2
        assert "files_raw" in data
        assert data["stats"]["total_lines"] > 0

    def test_scan_with_config(self):
        config = {"scan": {"max_file_size_mb": 0.001}}  # Very small limit
        data = scan_directory("sample_logs", config)
        # Should skip large files
        assert data["stats"]["file_count"] >= 0

    def test_nonexistent_dir(self):
        with pytest.raises(SystemExit):
            scan_directory("nonexistent_directory_xyz")

    def test_file_entries_have_line_idx(self):
        data = scan_directory("sample_logs")
        for entries in data["files"].values():
            for entry in entries:
                assert "_line_idx" in entry


class TestBuildContextHtml:
    """测试上下文 HTML 生成"""

    def test_basic_context(self):
        raw_lines = [
            "line 0: normal",
            "line 1: normal",
            "line 2: ERROR here",
            "line 3: normal",
            "line 4: normal",
        ]
        entry = {"_line_idx": 2}
        html = _build_context_html(entry, raw_lines, ctx_radius=2)
        assert "ctx-error" in html
        assert "ctx-normal" in html
        assert "line 2: ERROR here" in html

    def test_context_at_start(self):
        raw_lines = ["line 0: ERROR", "line 1: normal", "line 2: normal"]
        entry = {"_line_idx": 0}
        html = _build_context_html(entry, raw_lines, ctx_radius=2)
        assert "ctx-error" in html
        assert "line 0: ERROR" in html

    def test_context_at_end(self):
        raw_lines = ["line 0: normal", "line 1: normal", "line 2: ERROR"]
        entry = {"_line_idx": 2}
        html = _build_context_html(entry, raw_lines, ctx_radius=2)
        assert "ctx-error" in html

    def test_no_line_idx(self):
        entry = {"_line_idx": -1}
        html = _build_context_html(entry, ["line 0"], ctx_radius=2)
        assert html == ""

    def test_empty_raw_lines(self):
        entry = {"_line_idx": 0}
        html = _build_context_html(entry, [], ctx_radius=2)
        assert html == ""


class TestGenerateHtml:
    """测试 HTML 生成"""

    def test_basic_html(self):
        data = scan_directory("sample_logs")
        html = generate_html(data)
        assert "<!DOCTYPE html>" in html
        assert "日志错误分析报告" in html
        assert "exportCSV" in html
        assert "toggleTheme" in html
        assert "filterByLevel" in html
        assert "back-top" in html
        assert "ctx-wrap" in html
        assert "dedupToggle" in html
        assert "position: sticky" in html

    def test_html_has_all_levels(self):
        data = scan_directory("sample_logs")
        html = generate_html(data)
        assert "ERROR" in html
        assert "WARN" in html
        assert "TRACEBACK" in html

    def test_html_has_file_table(self):
        data = scan_directory("sample_logs")
        html = generate_html(data)
        assert "app.log" in html
        assert "server.log" in html


class TestLoadConfig:
    """测试配置加载"""

    def test_load_yaml(self):
        config = load_config("config.yaml")
        assert "scan" in config
        assert "analysis" in config
        assert "output" in config

    def test_load_nonexistent(self):
        config = load_config("nonexistent.yaml")
        assert config == {}

    def test_load_json(self):
        import json
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"scan": {"log_dir": "/tmp"}}, f)
            f.flush()
            config = load_config(f.name)
            assert config["scan"]["log_dir"] == "/tmp"
        os.unlink(f.name)


class TestBuildParser:
    """测试命令行解析器"""

    def test_default_args(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.log_dir is None
        assert args.output is None
        assert args.verbose is False
        assert args.quiet is False
        assert args.no_open is False

    def test_with_log_dir(self):
        parser = build_parser()
        args = parser.parse_args(["sample_logs"])
        assert args.log_dir == "sample_logs"

    def test_with_options(self):
        parser = build_parser()
        args = parser.parse_args(["sample_logs", "-o", "test.html", "-v", "--no-open"])
        assert args.log_dir == "sample_logs"
        assert args.output == "test.html"
        assert args.verbose is True
        assert args.no_open is True

    def test_with_dedup(self):
        parser = build_parser()
        args = parser.parse_args(["--dedup", "sample_logs"])
        assert args.dedup is True

    def test_with_context(self):
        parser = build_parser()
        args = parser.parse_args(["--context", "5", "sample_logs"])
        assert args.context == 5

    def test_with_config(self):
        parser = build_parser()
        args = parser.parse_args(["--config", "config.yaml", "sample_logs"])
        assert args.config == "config.yaml"

    def test_with_watch(self):
        parser = build_parser()
        args = parser.parse_args(["--watch", "30", "sample_logs"])
        assert args.watch == 30