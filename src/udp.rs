//! UDP 流量監控。
//!
//! UDP 沒有「連線」，Windows 的系統表只知道哪個程式綁了哪個本機埠，看不到對方是誰。
//! 要知道「哪個程式正在跟哪個外部位址收發 UDP」，必須靠 ETW 的 Microsoft-Windows-Kernel-Network
//! （事件 42/43 = IPv4 UDP 送出/收到，58/59 = IPv6），所以需要管理員權限。
//! QUIC（HTTP/3，UDP 443）、WebRTC、遊戲、VPN（WireGuard / Tailscale）都走這裡。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::net::is_public;

pub const SESSION: &str = "RuoRuoWatchdog-UDP";
const PROVIDER: &str = "7dd42a49-5329-4832-8dfd-43d979153a88"; // Microsoft-Windows-Kernel-Network
const KW_IPV4: u64 = 0x10;
const KW_IPV6: u64 = 0x20;
const MAX_FLOWS: usize = 20_000;

#[derive(Clone, Debug)]
pub struct Flow {
    pub pid: u32,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub local_port: u16,
    /// 第一個封包是對方先送來的（不是我們先送出去）
    pub started_inbound: bool,
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub last_seen: i64,
    /// 第一次看到這條流量時，該程式的執行檔路徑
    pub exe_path: Option<String>,
}

type Key = (u32, IpAddr, u16);

#[derive(Clone, Default)]
pub struct UdpFlows {
    inner: Arc<Mutex<HashMap<Key, Flow>>>,
    pub active: Arc<AtomicBool>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl UdpFlows {
    fn record(&self, pid: u32, is_send: bool, size: u64, saddr: IpAddr, sport: u16, daddr: IpAddr, dport: u16) {
        // 決定哪一邊是遠端：送出的封包，遠端就是目的地；收到的封包，遠端是來源。
        // 為了不依賴事件欄位的方向約定，收到時若只有其中一個是公開位址，就以公開的那個為遠端。
        let (rip, rport, lport) = if is_send {
            (daddr, dport, sport)
        } else {
            match (is_public(&saddr), is_public(&daddr)) {
                (false, true) => (daddr, dport, sport),
                _ => (saddr, sport, dport),
            }
        };
        if !is_public(&rip) {
            return; // 區網、本機、多點傳播這類流量不是這個工具要看的
        }
        let t = now();
        let mut g = self.inner.lock().unwrap();
        if g.len() >= MAX_FLOWS {
            g.retain(|_, f| t - f.last_seen < 600);
            if g.len() >= MAX_FLOWS {
                g.clear();
            }
        }
        let key = (pid, rip, rport);
        if !g.contains_key(&key) {
            // 新流量：趁程式還活著先記下路徑（dig、w32tm 這類很快就結束的程式，等掃描時已經查不到了）
            g.insert(
                key,
                Flow {
                    pid,
                    remote_ip: rip,
                    remote_port: rport,
                    local_port: lport,
                    started_inbound: !is_send,
                    sent_bytes: 0,
                    recv_bytes: 0,
                    last_seen: t,
                    exe_path: crate::procinfo::image_path(pid),
                },
            );
        }
        let f = g.get_mut(&key).unwrap();
        if is_send {
            f.sent_bytes += size;
        } else {
            f.recv_bytes += size;
        }
        f.local_port = lport;
        f.last_seen = t;
    }

    /// 最近 `within` 秒內有封包往來的流量；順便清掉太舊的
    pub fn active_flows(&self, within: i64) -> Vec<Flow> {
        let t = now();
        let mut g = self.inner.lock().unwrap();
        g.retain(|_, f| t - f.last_seen < 900);
        g.values().filter(|f| t - f.last_seen <= within).cloned().collect()
    }

    pub fn start_etw(&self) -> bool {
        use ferrisetw::parser::Parser;
        use ferrisetw::provider::Provider;
        use ferrisetw::schema_locator::SchemaLocator;
        use ferrisetw::trace::UserTrace;
        use ferrisetw::EventRecord;

        let me = self.clone();
        let cb = move |record: &EventRecord, loc: &SchemaLocator| {
            let (is_send, v6) = match record.event_id() {
                42 => (true, false),
                43 => (false, false),
                58 => (true, true),
                59 => (false, true),
                _ => return,
            };
            let Ok(schema) = loc.event_schema(record) else { return };
            let p = Parser::create(record, &schema);
            let addr = |name: &str| -> Option<IpAddr> {
                if let Ok(ip) = p.try_parse::<IpAddr>(name) {
                    return Some(ip);
                }
                if !v6 {
                    // 欄位型別沒標成 IP 時，當成 4 個位元組（記憶體順序就是網路順序）
                    let raw: u32 = p.try_parse(name).ok()?;
                    return Some(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())));
                }
                None
            };
            // 埠在事件裡是網路位元組順序
            let port = |name: &str| -> Option<u16> { p.try_parse::<u16>(name).ok().map(u16::swap_bytes) };

            let (Some(saddr), Some(daddr), Some(sport), Some(dport)) = (addr("saddr"), addr("daddr"), port("sport"), port("dport")) else { return };
            let pid: u32 = p.try_parse("PID").unwrap_or_else(|_| record.process_id());
            let size: u32 = p.try_parse("size").unwrap_or(0);
            me.record(pid, is_send, size as u64, saddr, sport, daddr, dport);
        };

        let provider = Provider::by_guid(PROVIDER).any(KW_IPV4 | KW_IPV6).add_callback(cb).build();
        // 固定名稱：上次被強制結束留下的 session 先停掉，避免累積
        let _ = ferrisetw::trace::stop_trace_by_name(SESSION);
        match UserTrace::new().named(SESSION.to_string()).enable(provider).start_and_process() {
            Ok(trace) => {
                self.active.store(true, Ordering::SeqCst);
                std::mem::forget(trace);
                true
            }
            Err(_) => false,
        }
    }
}
