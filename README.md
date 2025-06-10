# 🛡️ 100 Cybersecurity Projects

> Tập hợp 100 bài thực hành an ninh mạng do mình tự làm, nhằm lưu lại kinh nghiệm và phát triển bản thân.

# ✅ Lưu ý

- Dự án này được xây dựng với mục đích **học tập cá nhân**, không đại diện cho tổ chức hay chương trình đào tạo chính thức nào.
- **Tuyệt đối không áp dụng kỹ thuật** trong các bài thực hành vào hệ thống thật, hoặc hệ thống mà bạn không được phép can thiệp.
- Chỉ nên thực hành trong **môi trường kiểm soát**, như: máy ảo nội bộ, phòng lab, các nền tảng như TryHackMe, Hack The Box, DVWA, Metasploitable, v.v.
- Một số kỹ thuật mô phỏng hành vi của mã độc, khai thác lỗ hổng, tấn công mạng… có thể bị coi là **vi phạm pháp luật nếu sử dụng sai cách**.
- Tôi **không chịu trách nhiệm** cho bất kỳ hành vi nào gây ảnh hưởng đến cá nhân, tổ chức hoặc pháp lý liên quan đến việc sử dụng nội dung này.

# 📁 Danh mục

- [🔰 Beginner (01–30)](#-beginner-projects)
- [⚙ Intermediate (31–70)](#-intermediate-projects)
- [🧠 Advanced (71–100)](#-advanced-projects)

---

## 🔰 Beginner Projects

| STT | Dự án | Mô tả |
|-----|-------|-------|
| 001 | [Port Scanning with Nmap]() | Quét cổng cơ bản trên hệ thống mục tiêu bằng Nmap |
| 002 | [Network Packet Analysis]() | Phân tích gói tin mạng bằng Wireshark |
| 003 | [MAC Address Spoofing]() | Thay đổi địa chỉ MAC để ẩn danh hoặc mô phỏng thiết bị khác |
| 004 | [Brute Forcing SSH Login]() | Thử brute-force SSH trong môi trường giả lập |
| 005 | [Simple Password Cracker]() | Viết tool Python đơn giản để dò mật khẩu yếu |
| 006 | [SQL Injection Basics]() | Thực hành SQLi cơ bản trên DVWA |
| 007 | [Exploring XSS Vulnerabilities]() | Khai thác XSS trong ứng dụng web dễ tổn thương |
| 008 | [Wi-Fi Network Scanning]() | Quét mạng Wi-Fi bằng Aircrack-ng |
| 009 | [Social Engineering Simulation]() | Thiết kế kịch bản tấn công xã hội (không thực hiện ngoài đời) |
| 010 | [Information Gathering with Recon-ng]() | Thu thập thông tin tên miền bằng Recon-ng |
| 011 | [Email Phishing Simulation]() | Mô phỏng email lừa đảo cho mục đích giáo dục |
| 012 | [Simple Keylogger]() | Tạo keylogger cơ bản để hiểu cách hoạt động |
| 013 | [Setting Up a Honeypot]() | Triển khai honeypot đơn giản để ghi nhận truy cập trái phép |
| 014 | [Packet Sniffing with Scapy]() | Viết script Python để bắt gói tin bằng Scapy |
| 015 | [Google Dorking]() | Tìm kiếm thông tin nhạy cảm qua Google Dorks |
| 016 | [OSINT with Maltego]() | Khai thác dữ liệu mở và trực quan hóa bằng Maltego |
| 017 | [DNS Enumeration]() | Dò các bản ghi DNS bằng dnsenum hoặc Fierce |
| 018 | [ARP Spoofing Attack]() | Tấn công ARP spoofing trong lab |
| 019 | [Creating Fake Login Pages]() | Tạo form đăng nhập giả để hiểu kỹ thuật phishing |
| 020 | [Understanding Cookies & Sessions]() | Phân tích session và cookie trong ứng dụng web |
| 021 | [Creating Custom Wordlists]() | Tạo wordlist với Crunch phục vụ tấn công từ điển |
| 022 | [SQLmap Usage]() | Tự động khai thác lỗ hổng SQLi với SQLmap |
| 023 | [Firewall Evasion Basics]() | Thử các cách đơn giản để vượt qua firewall |
| 024 | [HTTP Headers Analysis]() | Phân tích header HTTP tìm thông tin nhạy cảm |
| 025 | [File Inclusion Vulnerabilities]() | Khai thác LFI và RFI trên DVWA |
| 026 | [VPNs and Proxychains]() | Cấu hình và sử dụng VPN & proxychain để ẩn danh |
| 027 | [Burp Suite Basics]() | Dùng Burp Suite để chặn và phân tích HTTP |
| 028 | [Command Injection]() | Khai thác lệnh hệ thống thông qua tham số web |
| 029 | [Hash Cracking with Hashcat]() | Dò mật khẩu từ hash với Hashcat |
| 030 | [Beginner CTF Setup]() | Thiết lập và chơi thử một thử thách CTF cơ bản |

## ⚙ Intermediate Projects

| STT | Dự án | Mô tả |
|-----|-------|-------|
| 031 | [Building a Vulnerability Scanner]() | Tạo công cụ quét lỗ hổng cơ bản bằng Python |
| 032 | [Privilege Escalation on Linux]() | Thực hành leo thang đặc quyền trên máy Linux giả lập |
| 033 | [Metasploit Basics]() | Khai thác lỗ hổng và hậu khai thác bằng Metasploit |
| 034 | [Directory Traversal Attack]() | Khai thác lỗi đọc file ngoài thư mục gốc |
| 035 | [Session Hijacking in HTTP]() | Cướp session thông qua cookie trong môi trường lab |
| 036 | [Exploiting CSRF Vulnerabilities]() | Hiểu và khai thác lỗ hổng CSRF |
| 037 | [Setting Up a C2 Server]() | Thiết lập server điều khiển (C2) cơ bản |
| 038 | [SSL Stripping with Bettercap]() | Thực hiện SSL Stripping trong môi trường an toàn |
| 039 | [Wireless Network Hacking]() | Bắt handshake WPA2 và thử bẻ khóa |
| 040 | [Code Injection in Web Apps]() | Chèn mã độc vào ứng dụng web đơn giản |
| 041 | [Advanced Social Engineering Toolkit]() | Tạo trang giả lập bằng SET |
| 042 | [Password Cracking with Hydra]() | Dùng Hydra brute-force dịch vụ phổ biến |
| 043 | [Network Mapping with Netdiscover]() | Quét thiết bị trong mạng LAN |
| 044 | [Automated SQLi with SQLmap]() | Tự động dò và khai thác SQLi nâng cao |
| 045 | [File Upload Exploitation]() | Tải lên shell qua lỗ hổng upload |
| 046 | [ARP Poisoning and MITM]() | Chèn gói tin độc qua ARP Poisoning |
| 047 | [Exploit Development Basics]() | Viết mã khai thác buffer overflow đơn giản |
| 048 | [OSINT with Shodan]() | Tìm thiết bị dễ tổn thương bằng Shodan |
| 049 | [Web App Scan with OWASP ZAP]() | Dò lỗi bảo mật trong web bằng ZAP |
| 050 | [Automated Scans with OpenVAS]() | Thiết lập và chạy quét bằng OpenVAS |
| 051 | [Simulated Phishing Campaign]() | Mô phỏng chiến dịch phishing nội bộ |
| 052 | [Reverse Engineering Basics]() | Phân tích nhị phân đơn giản để tìm lỗi |
| 053 | [Automated XSS Exploits]() | Viết script tự động phát hiện và khai thác XSS |
| 054 | [Build a Pentest Lab]() | Thiết lập lab mạng nội bộ cho thực hành |
| 055 | [Email Spoofing Lab]() | Thử giả mạo địa chỉ gửi email |
| 056 | [WebSockets Security Testing]() | Khai thác ứng dụng sử dụng WebSocket |
| 057 | [Remote Access with Netcat]() | Thiết lập shell đảo ngược hoặc bind shell |
| 058 | [Router Exploitation]() | Phân tích lỗ hổng router trong lab riêng |
| 059 | [Enum4Linux for SMB Enumeration]() | Liệt kê thông tin chia sẻ qua SMB |
| 060 | [Writing Web App Exploits]() | Viết mã khai thác cho lỗi bảo mật web cụ thể |
| 061 | [Using Wi-Fi Pineapple]() | Sử dụng WiFi Pineapple cho MITM |
| 062 | [Buffer Overflow on Linux]() | Thực hiện tấn công tràn bộ đệm trong Linux |
| 063 | [Wireless Recon with Airodump-ng]() | Dò thông tin Wi-Fi chi tiết với Airodump-ng |
| 064 | [Windows Privilege Escalation]() | Leo thang đặc quyền trên máy Windows |
| 065 | [Automated SQLi with jSQL]() | Sử dụng jSQL để khai thác SQLi dễ dàng |
| 066 | [Mobile App Pentesting]() | Phân tích ứng dụng Android đơn giản |
| 067 | [Intrusion Detection in Logs]() | Tìm dấu hiệu tấn công trong log mạng |
| 068 | [DNS Tunneling Lab]() | Thiết lập đường hầm DNS vượt firewall |
| 069 | [Brute Force Simulation]() | Giả lập tấn công brute-force toàn diện |
| 070 | [Browser Exploitation with BeEF]() | Sử dụng BeEF khai thác trình duyệt bị nhiễm |

## 🧠 Advanced Projects

| STT | Dự án | Mô tả |
|-----|-------|-------|
| 071  | [Advanced Buffer Overflow Exploitation]() | Phát triển khai thác buffer overflow nâng cao |
| 072  | [Exploiting Vulnerable APIs]() | Phân tích và khai thác API có lỗ hổng |
| 073  | [Automating CSRF Attacks]() | Viết script tự động thực hiện tấn công CSRF |
| 074  | [Custom Malware Development]() | Viết mã malware đơn giản trong môi trường lab |
| 075  | [Remote Keylogger in Python]() | Xây dựng keylogger gửi dữ liệu về từ xa |
| 076  | [Post-Exploitation with Metasploit]() | Tự động hoá tác vụ hậu khai thác với Metasploit |
| 077  | [Exploit Evasion Techniques]() | Áp dụng kỹ thuật né tránh phần mềm diệt virus |
| 078  | [Simulated Ransomware]() | Viết ransomware giả lập để hiểu quy trình mã hoá |
| 079  | [Browser Exploitation Scripts]() | Viết mã khai thác lỗ hổng trên trình duyệt |
| 080  | [Wi-Fi Deauthentication Attack]() | Ngắt kết nối thiết bị khỏi mạng không dây |
| 081  | [Python-based Remote Access Trojan]() | Tạo RAT cơ bản bằng Python |
| 082  | [Cross-Platform Reverse Shells]() | Viết reverse shell bằng nhiều ngôn ngữ khác nhau |
| 083  | [DLL Injection on Windows]() | Thực hành chèn mã vào tiến trình bằng DLL |
| 084  | [Privilege Escalation Scripting (Linux)]() | Viết script tìm điểm leo thang đặc quyền |
| 085  | [Exploiting SMB Vulnerabilities]() | Khai thác lỗ hổng SMB trên Windows |
| 086  | [Custom Bruteforce Tool]() | Tự viết công cụ brute-force cho form đăng nhập |
| 087  | [Advanced SQL Injection Toolkit]() | Tự động hoá các biến thể tấn công SQLi phức tạp |
| 088  | [Persistent Backdoor Deployment]() | Thiết lập backdoor tồn tại sau reboot |
| 089  | [NTLM Hash Dumping]() | Trích xuất và giải mã hash NTLM trên Windows |
| 090  | [Phishing for Social Media]() | Giả lập chiến dịch phishing cho mạng xã hội |
| 091  | [Advanced Network Tunneling]() | Dựng tunnel qua SSH, VPN để vượt firewall |
| 092  | [WAF Bypass Techniques]() | Vượt qua hệ thống tường lửa ứng dụng web |
| 093  | [Password Spraying Attack]() | Thực hiện password spraying trong lab an toàn |
| 094  | [Reverse Engineering Malware]() | Dịch ngược và phân tích phần mềm độc hại |
| 095  | [OSINT Automation with Python]() | Tự động thu thập OSINT bằng script Python |
| 096  | [Protocol Exploit Dev]() | Phát triển khai thác cho giao thức tùy chỉnh |
| 097  | [Simulating 2FA Bypass]() | Mô phỏng kỹ thuật vượt qua xác thực hai yếu tố |
| 098  | [Shellcode Execution via Injection]() | Thực thi shellcode qua kỹ thuật injection |
| 099  | [Zero-Day Vulnerability Research]() | Tìm hiểu và thử khai thác lỗ hổng chưa công bố |
| 100 | [End-to-End Penetration Testing]() | Thực hiện full pentest từ A đến Z |
