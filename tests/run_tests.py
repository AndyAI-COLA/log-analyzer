# -*- coding: utf-8 -*-
# 简易测试运行器 - 不依赖 pytest
# 用法: python run_tests.py

import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import (
    _normalize_level, _parse_line, _fingerprint, _deduplicate,
    _build_context_html, scan_directory, generate_html,
    load_config, build_parser,
)

passed = 0
failed = 0
errors = []

def test(name, func):
    global passed, failed
    try:
        func()
        passed += 1
        print("  PASS  " + name)
    except Exception as e:
        failed += 1
        errors.append((name, str(e)))
        print("  FAIL  " + name + ": " + str(e))

def assert_eq(a, b):
    if a != b:
        raise AssertionError("Expected %r, got %r" % (b, a))

def assert_in(a, b):
    if a not in b:
        raise AssertionError("Expected %r in %r" % (a, b))

print("=" * 60)
print("Log Analyzer Test Suite")
print("=" * 60)

print("\n[TestNormalizeLevel]")
test("warning_to_warn", lambda: assert_eq(_normalize_level("WARNING"), "WARN"))
test("critical_to_fatal", lambda: assert_eq(_normalize_level("CRITICAL"), "FATAL"))
test("error_upper", lambda: assert_eq(_normalize_level("ERROR"), "ERROR"))
test("error_lower", lambda: assert_eq(_normalize_level("error"), "ERROR"))
test("info", lambda: assert_eq(_normalize_level("INFO"), "INFO"))
test("debug", lambda: assert_eq(_normalize_level("DEBUG"), "DEBUG"))

print("\n[TestParseLine]")
def t1():
    r = _parse_line("[2024-01-15 10:40:00] [ERROR] [database] 连接超时: 无法连接到数据库 10.0.0.50:5432")
    assert r is not None
    assert_eq(r["level"], "ERROR")
    assert r["source"] in ("database", "unknown")
    assert_in("连接超时", r["message"])
    assert_eq(r["hour"], 10)
test("format_a_error", t1)

def t2():
    r = _parse_line("[2024-01-15 10:23:45] [INFO] [application] 应用启动成功")
    assert r is not None
    assert_eq(r["level"], "INFO")
test("format_b", t2)

def t3():
    r = _parse_line("16/Sep/2026:08:15:23 +0800 nginx - worker started")
    assert r is not None
    assert_eq(r["source"], "nginx")
test("nginx_format", t3)

test("empty_line", lambda: (assert_eq(_parse_line(""), None), assert_eq(_parse_line("   "), None)))
test("no_level", lambda: assert_eq(_parse_line("just random text"), None))

def t4():
    r = _parse_line("Traceback (most recent call last):")
    assert r is not None
    assert_eq(r["level"], "TRACEBACK")
test("traceback_line", t4)

print("\n[TestFingerprint]")
def t5():
    e1 = {"level": "ERROR", "source": "db", "raw": "连接 192.168.1.1:5432 超时"}
    e2 = {"level": "ERROR", "source": "db", "raw": "连接 10.0.0.5:5432 超时"}
    assert_eq(_fingerprint(e1), _fingerprint(e2))
test("same_pattern_diff_ip", t5)

def t6():
    e1 = {"level": "ERROR", "source": "db", "raw": "连接 192.168.1.1 超时"}
    e2 = {"level": "WARN", "source": "db", "raw": "连接 192.168.1.1 超时"}
    assert _fingerprint(e1) != _fingerprint(e2)
test("diff_level", t6)

print("\n[TestDeduplicate]")
def t7():
    entries = [
        {"level": "ERROR", "source": "db", "raw": "连接 192.168.1.1 超时", "timestamp": "10:00:00"},
        {"level": "ERROR", "source": "db", "raw": "连接 10.0.0.5 超时", "timestamp": "10:01:00"},
    ]
    r = _deduplicate(entries)
    assert_eq(len(r), 1)
    assert_eq(r[0]["_count"], 2)
test("merge_same", t7)

def t8():
    entries = [
        {"level": "ERROR", "source": "db", "raw": "连接超时", "timestamp": "10:00:00"},
        {"level": "ERROR", "source": "auth", "raw": "认证失败", "timestamp": "10:01:00"},
    ]
    r = _deduplicate(entries)
    assert_eq(len(r), 2)
test("keep_different", t8)

test("empty_dedup", lambda: assert_eq(_deduplicate([]), []))

print("\n[TestBuildContextHtml]")
def t9():
    lines = ["line 0", "line 1", "line 2: ERROR", "line 3", "line 4"]
    entry = {"_line_idx": 2}
    h = _build_context_html(entry, lines, ctx_radius=2)
    assert_in("ctx-error", h)
    assert_in("ctx-normal", h)
test("basic_context", t9)

test("no_idx", lambda: assert_eq(_build_context_html({"_line_idx": -1}, ["line"], ctx_radius=2), ""))
test("empty_ctx", lambda: assert_eq(_build_context_html({"_line_idx": 0}, [], ctx_radius=2), ""))

print("\n[TestScanDirectory]")
def t10():
    data = scan_directory("sample_logs")
    assert data["stats"]["total"] > 0
    assert_eq(data["stats"]["file_count"], 2)
    assert "files_raw" in data
test("scan_sample_logs", t10)

def t11():
    data = scan_directory("sample_logs", {"scan": {"max_file_size_mb": 0.001}})
    assert data["stats"]["file_count"] >= 0
test("scan_with_config", t11)

def t12():
    try:
        scan_directory("nonexistent_xyz")
        raise AssertionError("Should have raised SystemExit")
    except SystemExit:
        pass
test("nonexistent_dir", t12)

print("\n[TestGenerateHtml]")
def t13():
    data = scan_directory("sample_logs")
    h = generate_html(data)
    assert_in("<!DOCTYPE html>", h)
    assert_in("exportCSV", h)
    assert_in("toggleTheme", h)
    assert_in("filterByLevel", h)
    assert_in("back-top", h)
    assert_in("ctx-wrap", h)
    assert_in("dedupToggle", h)
    assert_in("position: sticky", h)
test("html_features", t13)

def t14():
    data = scan_directory("sample_logs")
    h = generate_html(data)
    assert_in("app.log", h)
    assert_in("server.log", h)
test("html_files", t14)

print("\n[TestLoadConfig]")
def t_yaml():
    import sys
    if 'yaml' not in sys.modules:
        try:
            import yaml
        except ImportError:
            print("  SKIP  load_yaml (PyYAML not installed)")
            return
    config = load_config("config.yaml")
    assert_in("scan", config)
test("load_yaml", t_yaml)
test("load_nonexistent", lambda: assert_eq(load_config("nonexistent.yaml"), {}))

print("\n[TestBuildParser]")
def t15():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.log_dir is None
    assert_eq(args.verbose, False)
test("parser_default", t15)

def t16():
    parser = build_parser()
    args = parser.parse_args(["sample_logs", "-o", "test.html", "-v", "--no-open"])
    assert_eq(args.log_dir, "sample_logs")
    assert_eq(args.output, "test.html")
    assert_eq(args.verbose, True)
    assert_eq(args.no_open, True)
test("parser_options", t16)

def t17():
    parser = build_parser()
    args = parser.parse_args(["--watch", "30", "sample_logs"])
    assert_eq(args.watch, 30)
test("parser_watch", t17)



print("\n[TestAlertManager]")

from analyzer import AlertManager

def t_alert_init():
    config = {"alert": {"enabled": True, "levels": ["FATAL", "CRITICAL"]}}
    mgr = AlertManager(config)
    assert mgr.enabled == True
    assert "FATAL" in mgr.alert_levels
    assert "CRITICAL" in mgr.alert_levels
test("alert_init", t_alert_init)

def t_alert_disabled():
    config = {"alert": {"enabled": False}}
    mgr = AlertManager(config)
    assert mgr.enabled == False
test("alert_disabled", t_alert_disabled)

def t_should_alert():
    config = {"alert": {"enabled": True, "levels": ["FATAL", "CRITICAL"]}}
    mgr = AlertManager(config)
    assert mgr.should_alert("FATAL") == True
    assert mgr.should_alert("CRITICAL") == True
    assert mgr.should_alert("ERROR") == False
    assert mgr.should_alert("WARN") == False
test("should_alert", t_should_alert)

def t_build_message():
    config = {"alert": {"enabled": True, "levels": ["FATAL"]}}
    mgr = AlertManager(config)
    stats = {
        "scan_time": "2024-01-15 10:00:00",
        "file_count": 2,
        "total": 5,
        "level_sorted": [("ERROR", 3), ("WARN", 2)],
        "top_sources": [("db", 3), ("auth", 2)],
    }
    msg = mgr._build_message(stats)
    assert "日志错误告警" in msg
    assert "文件数: 2" in msg
    assert "总错误数: 5" in msg
    assert "db: 3" in msg
test("build_message", t_build_message)

def t_cooldown():
    config = {"alert": {"enabled": True, "levels": ["FATAL"]}}
    mgr = AlertManager(config)
    # First call should pass
    assert mgr._check_cooldown("test") == True
    # Simulate recent alert
    mgr._last_alert_time["test"] = time.time()
    # Should be in cooldown
    assert mgr._check_cooldown("test") == False
test("cooldown", t_cooldown)

def t_send_alert_no_error():
    config = {"alert": {"enabled": True, "levels": ["FATAL"]}}
    mgr = AlertManager(config)
    data = {"stats": {"total": 5, "level_sorted": [("ERROR", 5)]}}
    # Should not send because ERROR not in alert levels
    mgr.send_alert(data)  # Should not raise
test("send_alert_no_match", t_send_alert_no_error)

def t_send_alert_disabled():
    config = {"alert": {"enabled": False}}
    mgr = AlertManager(config)
    data = {"stats": {"total": 5, "level_sorted": [("FATAL", 5)]}}
    mgr.send_alert(data)  # Should not raise
test("send_alert_disabled", t_send_alert_disabled)



print("\n[TestHistory]")

from analyzer import save_history, load_history, get_trend_data
import tempfile

def t_save_history():
    data = {
        "stats": {
            "scan_time": "2024-01-15 10:00:00",
            "total": 10,
            "file_count": 2,
            "total_lines": 100,
            "level_sorted": [("ERROR", 5), ("WARN", 5)],
        }
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        tmpfile = f.name
    try:
        save_history(data, tmpfile)
        history = load_history(tmpfile)
        assert len(history["records"]) == 1
        assert history["records"][0]["total"] == 10
    finally:
        import os
        os.unlink(tmpfile)
test("save_history", t_save_history)

def t_load_history_empty():
    history = load_history("nonexistent_history.json")
    assert history == {"records": []}
test("load_history_empty", t_load_history_empty)

def t_trend_data():
    history = {
        "records": [
            {"time": "2024-01-15 10:00:00", "total": 5},
            {"time": "2024-01-15 11:00:00", "total": 8},
            {"time": "2024-01-15 12:00:00", "total": 12},
        ]
    }
    trend = get_trend_data(history, hours=2)
    assert len(trend) == 2
    assert trend[0]["total"] == 8
    assert trend[1]["total"] == 12
test("trend_data", t_trend_data)

def t_trend_data_empty():
    trend = get_trend_data({"records": []}, hours=24)
    assert trend == []
test("trend_data_empty", t_trend_data_empty)



print("\n[TestJsonExport]")

from analyzer import generate_json

def t_json_basic():
    data = scan_directory("sample_logs")
    j = generate_json(data)
    report = json.loads(j)
    assert "meta" in report
    assert "errors" in report
    assert "level_summary" in report
    assert report["meta"]["total_errors"] > 0
    assert report["meta"]["file_count"] == 2
test("json_basic", t_json_basic)

def t_json_has_errors():
    data = scan_directory("sample_logs")
    j = generate_json(data)
    report = json.loads(j)
    assert len(report["errors"]) > 0
    # Check error structure
    err = report["errors"][0]
    assert "file" in err
    assert "level" in err
    assert "source" in err
    assert "message" in err
test("json_has_errors", t_json_has_errors)

def t_json_hourly():
    data = scan_directory("sample_logs")
    j = generate_json(data)
    report = json.loads(j)
    assert "hourly_distribution" in report
    assert isinstance(report["hourly_distribution"], dict)
test("json_hourly", t_json_hourly)

def t_json_files():
    data = scan_directory("sample_logs")
    j = generate_json(data)
    report = json.loads(j)
    assert "files" in report
    assert "app.log" in report["files"]
    assert "server.log" in report["files"]
test("json_files", t_json_files)

print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if errors:
    print("\nFailed tests:")
    for name, err in errors:
        print("  - %s: %s" % (name, err))

sys.exit(1 if failed else 0)