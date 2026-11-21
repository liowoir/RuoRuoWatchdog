//! 列出目前所有 TCP 連線（IPv4 + IPv6）與擁有它的 PID。不需要管理員權限。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Clone, Debug, serde::Serialize)]
pub struct Conn {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub state: &'static str,
    pub pid: u32,
}

fn state_name(s: u32) -> &'static str {
    match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn port(p: u32) -> u16 {
    u16::from_be((p & 0xffff) as u16)
}

fn fetch(af: u32) -> Vec<u8> {
    let mut size: u32 = 0;
    unsafe {
        let _ = GetExtendedTcpTable(None, &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
    }
    loop {
        let mut buf = vec![0u8; size as usize + 4096];
        let mut sz = buf.len() as u32;
        let r = unsafe {
            GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut sz, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
        };
        if r == 0 {
            return buf;
        }
        if r == 122 {
            // ERROR_INSUFFICIENT_BUFFER：表格在兩次呼叫之間變大了，再試一次
            size = sz;
            continue;
        }
        return Vec::new();
    }
}

pub fn tcp_connections() -> Vec<Conn> {
    let mut out = Vec::new();

    let buf = fetch(AF_INET.0 as u32);
    if !buf.is_empty() {
        unsafe {
            let t = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(t.table.as_ptr() as *const MIB_TCPROW_OWNER_PID, t.dwNumEntries as usize);
            for r in rows {
                out.push(Conn {
                    local_ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr))),
                    local_port: port(r.dwLocalPort),
                    remote_ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwRemoteAddr))),
                    remote_port: port(r.dwRemotePort),
                    state: state_name(r.dwState),
                    pid: r.dwOwningPid,
                });
            }
        }
    }

    let buf = fetch(AF_INET6.0 as u32);
    if !buf.is_empty() {
        unsafe {
            let t = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(t.table.as_ptr() as *const MIB_TCP6ROW_OWNER_PID, t.dwNumEntries as usize);
            for r in rows {
                let remote = Ipv6Addr::from(r.ucRemoteAddr);
                // IPv4-mapped 位址轉回 IPv4，方便比對
                let remote_ip = match remote.to_ipv4_mapped() {
                    Some(v4) => IpAddr::V4(v4),
                    None => IpAddr::V6(remote),
                };
                out.push(Conn {
                    local_ip: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                    local_port: port(r.dwLocalPort),
                    remote_ip,
                    remote_port: port(r.dwRemotePort),
                    state: state_name(r.dwState),
                    pid: r.dwOwningPid,
                });
            }
        }
    }
    out
}

/// 是否為「對外」的位址（排除本機、私有網段、Tailscale CGNAT、鏈路本地等）
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (o[0] == 100 && (64..=127).contains(&o[1])))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00)
        }
    }
}
