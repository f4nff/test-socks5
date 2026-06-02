
```toml
C:\Users\admin\Desktop\socks5-test>socks5_speedtest.exe -p "socks5://admin:pass@127.0.0.1:1080"
[*] 解析代理地址: socks5://admin:pass@127.0.0.1:1080

--- 开始 TCP 测试 (类似 nslookup -vc www.google.com) ---
[+] TCP 测试成功! 延迟: 352.92 ms

--- 开始 UDP 测试 (类似 nslookup www.google.com) ---
[+] UDP 测试成功! 延迟: 347.27 ms

C:\Users\admin\Desktop\socks5-test>socks5_speedtest.exe -p "socks5://admin:pass@[::1]:1080"
[*] 解析代理地址: socks5://admin:pass@[::1]:1080

--- 开始 TCP 测试 (类似 nslookup -vc www.google.com) ---
[+] TCP 测试成功! 延迟: 347.71 ms

--- 开始 UDP 测试 (类似 nslookup www.google.com) ---
[+] UDP 测试成功! 延迟: 354.75 ms

C:\Users\admin\Desktop\socks5-test>
```
