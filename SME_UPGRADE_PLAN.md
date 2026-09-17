# ��־�������� �� ��С��ҵ��������������

## Ŀ��

����ǰ"���˹��߼�"��Ŀ����Ϊ"��С��ҵ������"Ӧ�ã���������Ҫ��

- ��ά��Ա����һ�����𲢳���ʹ��
- ������Ա���԰�ȫ�ص����޸Ĵ���
- �����߿����ڳ�����ʱ��һʱ���յ�֪ͨ
- �Ŷӿ���Э��ά������չ����

---

## ��һ�׶Σ������ӹ̣�3-5�죩

> Ŀ�꣺��"����"������"����"

### 1.1 argparse �����и���

**��״**���� sys.argv �ֶ������������������׳����û�а�����Ϣ��

**��������**��

```
python analyzer.py --help

�÷�: analyzer.py [ѡ��] [��־Ŀ¼]

��־�������� - ɨ����־�ļ������ɴ����������

λ�ò���:
  log_dir                 ��־�ļ�����Ŀ¼ (Ĭ��: ./logs)

��ѡ����:
  -o, --output FILE       ��������ļ�·�� (Ĭ��: �Զ�����)
  -f, --format FORMAT     �����ʽ: html, csv, json (Ĭ��: html)
  -v, --verbose           ��ʾ��ϸɨ����Ϣ
  -q, --quiet             ��Ĭģʽ��ֻ�������
  --no-open               ���Զ��������
  --dedup                 ���ô���ȥ��
  --context N             ���������� (Ĭ��: 3)
  --watch SECONDS         ���ģʽ��ÿN��ɨ��һ��
  --config FILE           ָ�������ļ�·��
```

**�漰�ļ�**��analyzer.py �� main() ����

---

### 1.2 logging ģ���滻 print

**��״**��11 �� print() ���ã��޷������������

**��������**��

```python
import logging

# ������־
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('analyzer')

# �滻���� print
# Before: print(f"[INFO] ɨ��Ŀ¼: {log_dir}")
# After:  logger.info("ɨ��Ŀ¼: %s", log_dir)
```

**��־����滮**��
- DEBUG��ÿ�н������飨--verbose ʱ���ã�
- INFO��ɨ����ȡ�ͳ��ժҪ
- WARNING���������⡢��ʽ��ƥ��
- ERROR���ļ���ȡʧ�ܡ�Ŀ¼������
- CRITICAL���ڴ治�㡢����д��

**�漰�ļ�**��analyzer.py ȫ��

---

### 1.3 �����ļ�֧��

**��״**�����в�����Ҫͨ�������д��ݣ��޷��̻����á�

**�½��ļ�**��config.yaml

```yaml
# ��־�������������ļ�
# �÷�: python analyzer.py --config config.yaml

# ɨ������
scan:
  log_dir: ./logs                    # ��־Ŀ¼
  pattern: "*.log"                   # �ļ�ƥ��ģʽ
  exclude:                           # �ų����ļ�/Ŀ¼
    - "*.tmp"
    - "archive/"
  max_file_size_mb: 100              # ���ļ��������(MB)
  encoding: utf-8                    # Ĭ�ϱ���

# ��������
analysis:
  levels:                            # Ҫ��ȡ�ļ���
    - ERROR
    - WARN
    - WARNING
    - FATAL
    - CRITICAL
    - Exception
    - Traceback
  dedup: true                        # Ĭ������ȥ��
  context_lines: 3                   # ����������
  custom_patterns: []                # �Զ�����־��ʽ����

# �������
output:
  format: html                       # html | csv | json
  dir: ./reports                     # ���Ŀ¼
  auto_open: true                    # �Զ��������
  filename_template: "report_{date}_{time}"  # �ļ���ģ��

# �澯���ã��ڶ��׶�ʵ�֣�
alert:
  enabled: false
  levels: ["FATAL", "CRITICAL"]
  channels: []
  # - type: webhook
  #   url: https://oapi.dingtalk.com/robot/send?access_token=xxx
  # - type: email
  #   smtp_host: smtp.example.com
  #   smtp_port: 465
  #   use_ssl: true
  #   username: ""
  #   password: ""
  #   from_addr: "alert@example.com"
  #   to_addrs: ["admin@example.com"]

# ������ã��ڶ��׶�ʵ�֣�
watch:
  enabled: false
  interval_seconds: 30
  alert_on_new_errors: true
```

**ʵ�ַ�ʽ**��ʹ�� PyYAML���� Python �� json ��Ϊ��ѡ��

**�漰�ļ�**���½� config.yaml���޸� analyzer.py

---

### 1.4 ��Ԫ���Կ��

**�½��ļ�**��tests/test_analyzer.py

```python
import pytest
from analyzer import (
    _normalize_level,
    _parse_line,
    _fingerprint,
    _deduplicate,
    scan_directory,
    generate_html,
)

class TestNormalizeLevel:
    """���Լ����׼��"""

    def test_warning_to_warn(self):
        assert _normalize_level("WARNING") == "WARN"

    def test_critical_to_fatal(self):
        assert _normalize_level("CRITICAL") == "FATAL"

    def test_already_upper(self):
        assert _normalize_level("ERROR") == "ERROR"

    def test_lowercase(self):
        assert _normalize_level("error") == "ERROR"


class TestParseLine:
    """������־�н���"""

    def test_format_a(self):
        line = "2024-01-15 10:23:45 [ERROR] [database] ���ӳ�ʱ"
        result = _parse_line(line)
        assert result is not None
        assert result["level"] == "ERROR"
        assert result["source"] == "database"
        assert "���ӳ�ʱ" in result["message"]

    def test_format_b(self):
        line = "[2024-01-15 10:23:45] [INFO] [server] ������"
        result = _parse_line(line)
        assert result is not None
        assert result["level"] == "INFO"

    def test_empty_line(self):
        assert _parse_line("") is None
        assert _parse_line("   ") is None

    def test_no_level(self):
        line = "just some random text without level"
        result = _parse_line(line)
        assert result is None


class TestFingerprint:
    """����ָ������"""

    def test_same_pattern_different_ip(self):
        e1 = {"level": "ERROR", "source": "db", "raw": "���� 192.168.1.1:5432 ��ʱ"}
        e2 = {"level": "ERROR", "source": "db", "raw": "���� 10.0.0.5:5432 ��ʱ"}
        assert _fingerprint(e1) == _fingerprint(e2)

    def test_different_level(self):
        e1 = {"level": "ERROR", "source": "db", "raw": "���� 192.168.1.1 ��ʱ"}
        e2 = {"level": "WARN", "source": "db", "raw": "���� 192.168.1.1 ��ʱ"}
        assert _fingerprint(e1) != _fingerprint(e2)


class TestDeduplicate:
    """����ȥ�ع���"""

    def test_merge_same_errors(self):
        entries = [
            {"level": "ERROR", "source": "db", "raw": "���� 192.168.1.1 ��ʱ", "timestamp": "10:00:00"},
            {"level": "ERROR", "source": "db", "raw": "���� 10.0.0.5 ��ʱ", "timestamp": "10:01:00"},
        ]
        result = _deduplicate(entries)
        assert len(result) == 1
        assert result[0]["_count"] == 2

    def test_keep_different_errors(self):
        entries = [
            {"level": "ERROR", "source": "db", "raw": "���ӳ�ʱ", "timestamp": "10:00:00"},
            {"level": "ERROR", "source": "auth", "raw": "��֤ʧ��", "timestamp": "10:01:00"},
        ]
        result = _deduplicate(entries)
        assert len(result) == 2


class TestScanDirectory:
    """����Ŀ¼ɨ��"""

    def test_scan_sample_logs(self):
        data = scan_directory("sample_logs")
        assert data["stats"]["total"] > 0
        assert data["stats"]["file_count"] == 2
        assert "files_raw" in data

    def test_nonexistent_dir(self):
        with pytest.raises(SystemExit):
            scan_directory("nonexistent_directory")


class TestGenerateHtml:
    """���� HTML ����"""

    def test_basic_html(self):
        data = scan_directory("sample_logs")
        html = generate_html(data)
        assert "<!DOCTYPE html>" in html
        assert "��־�����������" in html
        assert "exportCSV" in html
        assert "toggleTheme" in html
        assert "filterByLevel" in html
```

**���Ը�����Ŀ��**�����ĺ��� > 80%

**�漰�ļ�**���½� tests/ Ŀ¼��tests/test_analyzer.py��tests/conftest.py

---

### 1.5 ��������ǿ

**��״**�����ֱ߽����δ�����

**��������**��

```python
# 1. Ŀ¼������ʱ���Ѻ���ʾ
def scan_directory(log_dir: str) -> dict:
    log_path = Path(log_dir)
    if not log_path.is_dir():
        logger.error("Ŀ¼������: %s", log_dir)
        logger.info("����·���Ƿ���ȷ����ʹ�� --help �鿴�÷�")
        sys.exit(1)

# 2. �ļ���С����
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
for log_file in sorted(log_path.rglob("*.log")):
    if log_file.stat().st_size > MAX_FILE_SIZE:
        logger.warning("�������ļ�: %s (%.1f MB)", rel, log_file.stat().st_size / 1024 / 1024)
        continue

# 3. ��Ŀ��������
MAX_ENTRIES = 100000
if len(all_entries) >= MAX_ENTRIES:
    logger.warning("�Ѵﵽ�����Ŀ���� (%d)�����ּ�¼���ܱ��ض�", MAX_ENTRIES)
    break

# 4. д��ʧ�ܴ���
try:
    with open(output, "w", encoding="utf-8") as f:
        f.write(report_html)
except PermissionError:
    logger.error("û��д��Ȩ��: %s", output)
    sys.exit(1)
except OSError as e:
    logger.error("д���ļ�ʧ��: %s", e)
    sys.exit(1)
```

---

## �ڶ��׶Σ���ά��ǿ��3-5�죩

> Ŀ�꣺��"�ֶ���"������"�Զ���"

### 2.1 Watch ���ģʽ

**ʵ�ַ�ʽ**����ʱѭ��ɨ�� + �仯���

```python
import time

def watch_mode(log_dir, output, interval=30):
    """���ģʽ����ʱɨ����־Ŀ¼"""
    logger.info("������ģʽ��ÿ %d ��ɨ��һ��", interval)
    last_hash = None

    while True:
        try:
            data = scan_directory(log_dir)
            current_hash = hash(str(data["stats"]))

            if last_hash and current_hash != last_hash:
                logger.warning("��⵽�´���")
                # ���ɱ���
                report_html = generate_html(data)
                # ���͸澯�������׶Σ�
                # send_alert(data)

            last_hash = current_hash
            logger.info("ɨ����ɣ��ȴ� %d ��...", interval)
            time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("�����ֹͣ")
            break
        except Exception as e:
            logger.error("ɨ���쳣: %s", e)
            time.sleep(interval)
```

**�÷�**��
```bash
python analyzer.py --watch 30 --config config.yaml
```

---

### 2.2 �澯֪ͨ����

**֧������**��

| ���� | ʵ�ַ�ʽ | ���ó��� |
|------|---------|---------|
| ���������� | Webhook POST | �����Ŷ� |
| ��ҵ΢�� | Webhook POST | �����Ŷ� |
| �ʼ� | SMTP | ͨ�� |
| Bark | HTTP GET | iOS ���� |
| Slack | Webhook POST | �����Ŷ� |

**ʵ�ִ���**��

```python
import urllib.request
import json

class AlertManager:
    def __init__(self, config):
        self.channels = config.get("channels", [])
        self.levels = config.get("levels", ["FATAL", "CRITICAL"])

    def should_alert(self, level: str) -> bool:
        return level in self.levels

    def send(self, data: dict):
        """���͸澯���������õ�����"""
        stats = data["stats"]
        message = self._build_message(stats)

        for channel in self.channels:
            try:
                if channel["type"] == "webhook":
                    self._send_webhook(channel["url"], message)
                elif channel["type"] == "email":
                    self._send_email(channel, message)
            except Exception as e:
                logger.error("�澯����ʧ�� [%s]: %s", channel["type"], e)

    def _build_message(self, stats):
        """�����澯��Ϣ"""
        lines = [
            "?? ��־����澯",
            f"ʱ��: {stats['scan_time']}",
            f"�ļ���: {stats['file_count']}",
            f"��������: {stats['total']}",
        ]
        for level, count in stats["level_sorted"]:
            lines.append(f"  {level}: {count}")
        return "\n".join(lines)

    def _send_webhook(self, url, message):
        """���� Webhook ֪ͨ"""
        payload = json.dumps({"msgtype": "text", "text": {"content": message}})
        req = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)

    def _send_email(self, config, message):
        """�����ʼ�֪ͨ"""
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText(message, "plain", "utf-8")
        msg["Subject"] = "��־����澯"
        msg["From"] = config["username"]
        msg["To"] = ", ".join(config["to_addrs"])

        with smtplib.SMTP_SSL(config["smtp_host"], config["smtp_port"]) as server:
            server.login(config["username"], config["password"])
            server.send_message(msg)
```

---

### 2.3 ��ʷ����׷��

**ʵ�ַ�ʽ**��ÿ�����м�¼ժҪ�� history.json

```json
{
  "records": [
    {
      "time": "2024-01-15T10:00:00",
      "total": 16,
      "levels": {"ERROR": 8, "WARN": 7, "TRACEBACK": 1},
      "files": 2,
      "total_lines": 91
    }
  ]
}
```

**������������ͼ**���Աȱ��� vs �ϴ� vs 7��ƽ��

---

## �����׶Σ�������Э����2-3�죩

> Ŀ�꣺��"������"������"�Ŷ���"

### 3.1 Docker ������

**�½��ļ�**��Dockerfile

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# ���ƴ���
COPY analyzer.py .
COPY config.yaml .

# ����Ŀ¼
RUN mkdir -p /logs /reports

# ����
ENTRYPOINT ["python", "analyzer.py", "--config", "config.yaml"]
CMD ["/logs"]
```

**�÷�**��
```bash
# ����
docker build -t log-analyzer .

# ����
docker run --rm \
  -v /var/log/myapp:/logs \
  -v $(pwd)/reports:/reports \
  log-analyzer

# ���ģʽ
docker run --rm -d \
  --name log-monitor \
  -v /var/log/myapp:/logs \
  -v $(pwd)/reports:/reports \
  log-analyzer --watch 60
```

---

### 3.2 GitHub Actions CI/CD

**�½��ļ�**��.github/workflows/test.yml

```yaml
name: Test

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: pip install pytest pyyaml

      - name: Run tests
        run: pytest tests/ -v --tb=short

      - name: Run analyzer
        run: python analyzer.py sample_logs --no-open
```

---

### 3.3 ��Ŀ�ṹ������̬

```
log-analyzer/
������ analyzer.py              # ������
������ config.yaml              # �����ļ�
������ Dockerfile               # Docker ����
������ docker-compose.yml       # Docker Compose
������ requirements.txt         # ������pytest, pyyaml��
������ README.md                # ʹ���ĵ�
������ OPTIMIZATION.md          # �Ż�����
������ SME_UPGRADE_PLAN.md      # ���ļ�
������ .gitignore
������ .github/
��   ������ workflows/
��       ������ test.yml         # CI/CD
������ tests/
��   ������ __init__.py
��   ������ conftest.py          # ��������
��   ������ test_analyzer.py     # ���Ĳ���
��   ������ test_html.py         # HTML ���ɲ���
������ sample_logs/
��   ������ app.log
��   ������ server.log
������ reports/
    ������ (���ɵı���)
```

---

## ʵʩʱ���

```
��1�� ������������������������������������������������������������������������
  Day 1-2: argparse ���� + logging �滻
  Day 3:   �����ļ�֧�� (config.yaml)
  Day 4-5: ��Ԫ���Կ�� + ���Ĳ�������

��2�� ������������������������������������������������������������������������
  Day 1-2: ��������ǿ + �߽����
  Day 3-4: Watch ���ģʽ
  Day 5:   �澯֪ͨ���� (����/�ʼ�)

��3�� ������������������������������������������������������������������������
  Day 1:   ��ʷ����׷��
  Day 2:   Docker ������
  Day 3:   CI/CD ����
  Day 4-5: �ĵ����� + ���ղ���
```

---

## ���ձ�׼

������н׶κ���ĿӦ���㣺

| ����� | ��׼ |
|--------|------|
| �����а��� | `python analyzer.py --help` ��������÷� |
| �����ļ� | ֧�� YAML ���ã������ɸ��� |
| ���Ը��� | pytest ͨ���������� > 80% |
| ��־��� | ʹ�� logging��֧�� --verbose / --quiet |
| Watch ģʽ | `--watch 30` ������� |
| �澯֪ͨ | FATAL ���𴥷�����/�ʼ�֪ͨ |
| Docker | `docker run` һ������ |
| CI/CD | push �����Զ����� |
| �ĵ� | README ������װ�����á�ʹ�á�����˵�� |
| ������ | ���Ŵ���Ŀ¼�����ڡ��ļ�����Ȩ�޲��� |
