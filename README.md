# NetSentinel AI

🛡️ **Copilot phát hiện bất thường mạng thông minh & phân tích mối đe dọa.**

NetSentinel AI tự động phân tích nhật ký lưu lượng thô (**PCAP** / metadata luồng) để phát
hiện hoạt động độc hại và mối đe dọa zero-day theo thời gian thực, rồi giải thích logic mối
đe dọa bằng ngôn ngữ tự nhiên và sinh quy tắc phát hiện có thể action ngay.

## Tính năng chính

1. **Tóm tắt lưu lượng** — tiền xử lý PCAP/flow, trích xuất siêu dữ liệu kết nối
   (luồng IP/cổng, mẫu beacon, truy vấn DNS bất thường).
2. **Lý luận mối đe dọa dựa trên AI** — dùng **Meta Model API (Llama Cloud)** để phân tích
   dữ liệu đáng ngờ, ánh xạ hành vi vào khung **MITRE ATT&CK**, giải thích bằng ngôn ngữ tự nhiên.
3. **Phản ứng sự cố tự động** — sinh quy tắc **Snort/Suricata** và **YARA**, kèm các bước
   giảm thiểu, qua giao diện trò chuyện tương tác cho nhà phân tích.

## Architecture

```
[PCAP / Flow metadata]
   → ingest/      (pcap_parser, flow_parser)
   → features/    (beacon, dns, scan, exfil heuristics)
   → engine/      (detector orchestrator → suspicious events)
   → llm/         (LlamaClient → MITRE mapping + natural-language reasoning)
   → response/    (Snort/Suricata, YARA, playbooks)
   → ui/          (Chainlit chat + terminal fallback)
```

## Cài đặt

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt
# hoặc cài gọn để chạy offline (không cần UI/LLM):
pip install scapy pydantic python-dotenv PyYAML pytest
```

## Cấu hình

Sao chép `.env.example` thành `.env` và điền **Meta Model API key** (từ Llama Cloud):

```
LLAMA_API_KEY=your_key
LLAMA_MODEL=meta/llama-4-maverick-17b-128e-instruct-fp8
```

Không có key, pipeline vẫn hoạt động ở chế độ **offline** (dùng lý luận heuristic cục bộ).

## Sử dụng nhanh

```bash
# 1) Sinh dữ liệu demo (PCAP synthetic gồm beacon, DGA, scan, tunnel, exfil)
python scripts/generate_demo_pcap.py data/demo.pcap

# 2) Phân tích (dùng PYTHONPATH=src)
$env:PYTHONPATH="src"                      # PowerShell
python -m netsentinel analyze data/demo.pcap --rules

# JSON output:
python -m netsentinel analyze data/demo.pcap --format json

# 3) Chat tương tác trên terminal
python -m netsentinel.ui.terminal

# 4) Chat UI (tuỳ chọn, cài chainlit trước)
chainlit run src/netsentinel/ui/app.py
```

## Các detector heuristics

| Detector        | Tín hiệu                                              | MITRE            |
|-----------------|-------------------------------------------------------|------------------|
| `beacon`        | Kết nối định kỳ, jitter thấp (phân tích inter-arrival) | T1071.001        |
| `dga`           | Tên miền entropy cao, dạng máy sinh ra                | T1568.002        |
| `nxdomain_storm`| Bùng nổ truy vấn NXDOMAIN từ một host                 | T1568.002        |
| `dns_tunneling` | Truy vấn TXT/label dài lặp lại tới 1 domain           | T1071.004        |
| `port_scan`     | Quét nhiều cổng trong cửa sổ ngắn                     | T1046            |
| `exfiltration`  | Outbound lớn bất đối xứng (upload >> download)         | T1041            |

## Kiểm thử

```bash
$env:PYTHONPATH="src"
python -m pytest -q
```

## Cấu trúc thư mục

```
netsentinel/
├── config/config.yaml      # ngưỡng phát hiện + cấu hình Llama
├── scripts/                # sinh dữ liệu demo
├── src/netsentinel/        # package chính
│   ├── ingest/  features/  engine/  llm/  response/  ui/
│   ├── pipeline.py         # orchestrator end-to-end
│   └── cli.py              # CLI
└── tests/                  # unit + integration tests
```

> **Lưu ý:** đây là công cụ phòng thủ/demo với dữ liệu synthetic. Không chạy trên lưu lượng
> thật nếu không có sự cho phép rõ ràng của chủ sở hữu hệ thống.
