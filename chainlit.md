# 🛡️ NetSentinel AI

**Copilot phát hiện bất thường mạng thông minh & phân tích mối đe dọa.**

NetSentinel phân tích PCAP / metadata luồng, phát hiện hành vi độc hại (beacon C2, DGA,
NXDOMAIN storm, DNS tunneling, port scan, exfiltration), ánh xạ **MITRE ATT&CK** và sinh
rule **Snort/Suricata** + **YARA** cùng các bước giảm thiểu.

## Cách sử dụng

1. Gửi **đường dẫn file** (ví dụ `data/demo.pcap`) hoặc đính kèm file `.pcap/.csv/.json`.
2. Hệ thống tự trích xuất luồng → phát hiện bất thường → lý luận mối đe dọa.
3. Đặt câu hỏi bằng ngôn ngữ tự nhiên:

| Lệnh | Ý nghĩa |
|------|---------|
| `summary` | Tổng quan kết quả |
| `events` | Danh sách sự kiện |
| `beacons` | Liệt kê C2 beacon |
| `explain 1` | Giải thích sự kiện #1 |
| `rules` | Rule Snort/Suricata + YARA |
| `playbook 1` | Các bước giảm thiểu cho sự kiện #1 |
| `help` | Danh sách lệnh |

