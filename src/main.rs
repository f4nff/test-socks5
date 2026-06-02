use clap::Parser;
use socket2::{SockRef, TcpKeepalive};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use url::Url;

/// www.google.com 的标准 DNS 查询包 (Type A, Class IN)
const DNS_QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";

#[derive(Parser, Debug)]
#[command(author, version, about = "SOCKS5 Proxy TCP/UDP Speed Test Tool with Keep-Alive")]
struct Args {
    /// SOCKS5 代理地址 (自动识别 IPv4 或 IPv6)
    #[arg(short, long, default_value = "socks5://user:pass@127.0.0.1:1080")]
    proxy: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let proxy_url_str = &args.proxy;

    println!("[*] 解析代理地址: {}", proxy_url_str);
    let proxy_url = match Url::parse(proxy_url_str) {
        Ok(url) => url,
        Err(e) => {
            eprintln!("[!] 代理地址解析失败: {}", e);
            return;
        }
    };

    println!("\n--- 开始 TCP 测试 (类似 nslookup -vc www.google.com) ---");
    match test_tcp(&proxy_url).await {
        Ok(latency) => println!("[+] TCP 测试成功! 延迟: {:.2} ms", latency),
        Err(e) => eprintln!("[!] TCP 测试失败: {}", e),
    }

    println!("\n--- 开始 UDP 测试 (类似 nslookup www.google.com) ---");
    match test_udp(&proxy_url).await {
        Ok(latency) => println!("[+] UDP 测试成功! 延迟: {:.2} ms", latency),
        Err(e) => eprintln!("[!] UDP 测试失败: {}", e),
    }
}

/// 配置 TCP 基础心跳保活机制，防止 NAT 网关或代理服务端主动切断静默连接
fn enable_tcp_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    let sock_ref = SockRef::from(stream);
    
    // 跨平台 Keep-Alive 配置 (兼容 Windows 和 Linux)
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))     // 闲置 30 秒后开始发送心跳
        .with_interval(Duration::from_secs(10)); // 心跳包发送间隔 10 秒

    sock_ref.set_tcp_keepalive(&keepalive)
}

/// SOCKS5 握手与认证
async fn socks5_handshake(stream: &mut TcpStream, url: &Url) -> Result<(), Box<dyn std::error::Error>> {
    let has_auth = !url.username().is_empty();
    let methods = if has_auth { vec![0x05, 0x02, 0x00, 0x02] } else { vec![0x05, 0x01, 0x00] };
    
    stream.write_all(&methods).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;

    if resp[1] == 0x02 {
        // 用户名密码认证
        let user = url.username().as_bytes();
        let pass = url.password().unwrap_or("").as_bytes();
        let mut auth_req = vec![0x01, user.len() as u8];
        auth_req.extend_from_slice(user);
        auth_req.push(pass.len() as u8);
        auth_req.extend_from_slice(pass);

        stream.write_all(&auth_req).await?;
        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await?;
        if auth_resp[1] != 0x00 {
            return Err("SOCKS5 认证失败 (密码错误)".into());
        }
    } else if resp[1] != 0x00 {
        return Err("SOCKS5 代理不支持请求的认证方式".into());
    }
    Ok(())
}

async fn test_tcp(url: &Url) -> Result<f64, Box<dyn std::error::Error>> {
    let addrs = url.socket_addrs(|| Some(1080))?;
    let start = Instant::now();

    // 1. 连接代理并开启底层的 TCP Keep-Alive
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(addrs.as_slice())).await??;
    enable_tcp_keepalive(&stream)?;
    socks5_handshake(&mut stream, url).await?;

    // 2. 发送 CONNECT 请求到 8.8.8.8:53 (Google DNS)
    let connect_req = vec![0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x00, 53];
    stream.write_all(&connect_req).await?;

    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;
    if resp_header[1] != 0x00 {
        return Err(format!("CONNECT 失败, SOCKS5 错误码: {}", resp_header[1]).into());
    }

    // 读取剩下的 BND.ADDR 和 BND.PORT
    match resp_header[3] {
        0x01 => { let mut skip = [0u8; 6]; stream.read_exact(&mut skip).await?; },
        0x04 => { let mut skip = [0u8; 18]; stream.read_exact(&mut skip).await?; },
        _ => return Err("未知的地址类型".into()),
    }

    // 3. 发送 TCP DNS 请求 (需要加上 2 字节的长度前缀)
    let mut tcp_dns_query = vec![0x00, DNS_QUERY.len() as u8];
    tcp_dns_query.extend_from_slice(DNS_QUERY);
    stream.write_all(&tcp_dns_query).await?;

    // 4. 读取响应
    let mut length_buf = [0u8; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut length_buf)).await??;

    let duration = start.elapsed();
    Ok(duration.as_secs_f64() * 1000.0)
}

async fn test_udp(url: &Url) -> Result<f64, Box<dyn std::error::Error>> {
    let addrs = url.socket_addrs(|| Some(1080))?;
    let start = Instant::now();

    // 1. TCP 握手 (UDP Associate 必须保持一个 TCP 控制连接) 并且开启底层的 TCP Keep-Alive
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(addrs.as_slice())).await??;
    enable_tcp_keepalive(&stream)?;
    socks5_handshake(&mut stream, url).await?;

    // 2. 请求 UDP ASSOCIATE (地址全0表示让代理自己分配)
    let udp_req = vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&udp_req).await?;

    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;
    if resp_header[1] != 0x00 {
        return Err(format!("UDP ASSOCIATE 失败, 错误码: {}", resp_header[1]).into());
    }

    // 3. 解析代理返回的 UDP 转发地址和端口 (BND.ADDR / BND.PORT)
    let bnd_ip: IpAddr;
    let bnd_port: u16;

    if resp_header[3] == 0x01 { // IPv4
        let mut addr = [0u8; 4]; stream.read_exact(&mut addr).await?;
        bnd_ip = IpAddr::V4(Ipv4Addr::from(addr));
        let mut port = [0u8; 2]; stream.read_exact(&mut port).await?;
        bnd_port = u16::from_be_bytes(port);
    } else if resp_header[3] == 0x04 { // IPv6
        let mut addr = [0u8; 16]; stream.read_exact(&mut addr).await?;
        let addr_arr: [u8; 16] = addr.try_into().unwrap();
        bnd_ip = IpAddr::V6(Ipv6Addr::from(addr_arr));
        let mut port = [0u8; 2]; stream.read_exact(&mut port).await?;
        bnd_port = u16::from_be_bytes(port);
    } else {
        return Err("不支持的 BND.ADDR 类型".into());
    }

    let mut proxy_udp_addr = SocketAddr::new(bnd_ip, bnd_port);
    // 很多 SOCKS5 代理返回 0.0.0.0 或 ::，这意味着我们需要直接发给控制连接的 IP
    if bnd_ip.is_unspecified() {
        proxy_udp_addr.set_ip(stream.peer_addr()?.ip());
    }

    // 4. 动态绑定本地 UDP 套接字 (兼容 IPv4 和 IPv6)
    let bind_addr = if proxy_udp_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let local_socket = UdpSocket::bind(bind_addr).await?;
    
    // SOCKS5 UDP Header: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2)
    // 目标依然是 8.8.8.8:53
    let mut udp_payload = vec![0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 53];
    udp_payload.extend_from_slice(DNS_QUERY);

    local_socket.send_to(&udp_payload, &proxy_udp_addr).await?;

    // 5. 等待 UDP 响应
    let mut recv_buf = [0u8; 1024];
    timeout(Duration::from_secs(5), local_socket.recv_from(&mut recv_buf)).await??;

    let duration = start.elapsed();
    Ok(duration.as_secs_f64() * 1000.0)
}