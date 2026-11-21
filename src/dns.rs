//! 網域來源解析，四層來源（可信度由高到低）：
//! 1. ETW「Microsoft-Windows-DNS-Client」事件：即時知道「哪個程式（PID）查了哪個網域、得到哪些 IP」。需要以管理員執行。
//! 2. Windows DNS 快取（WMI: root\StandardCimv2 / MSFT_DNSClientCache）：不需管理員；有些系統這裡是空的。
//! 3. TLS 憑證：對 HTTPS 連線的遠端 IP 做一次 TLS 握手，讀憑證上登記的網域（不送任何資料）。
//! 4. PTR 反查。
//!
//! 盲點：瀏覽器若開了「安全 DNS（DoH）」會自己解析，不經過 Windows，第 1、2 層都看不到。

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(rename = "MSFT_DNSClientCache")]
#[serde(rename_all = "PascalCase")]
struct CacheEntry {
    entry: Option<String>,
    data: Option<String>,
    #[serde(rename = "Type")]
    kind: Option<u16>,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq)]
pub enum Source {
    Etw,
    Cache,
    Cert,
}

#[derive(Default)]
struct Inner {
    /// IP → (網域 → 最後看到的時間)
    names: HashMap<IpAddr, HashMap<String, i64>>,
    /// (PID, IP) → 網域：這個程式自己查到的，最準
    by_pid: HashMap<(u32, IpAddr), HashMap<String, i64>>,
    /// CNAME：別名 → 原始查詢名稱
    cname_parent: HashMap<String, String>,
    ptr: HashMap<IpAddr, Option<String>>,
    ptr_queue: VecDeque<IpAddr>,
    ptr_pending: HashSet<IpAddr>,
    cert: HashMap<(IpAddr, u16), Vec<String>>,
    cert_queue: VecDeque<(IpAddr, u16)>,
    cert_pending: HashSet<(IpAddr, u16)>,
}

#[derive(Clone, Default)]
pub struct Resolver {
    inner: Arc<Mutex<Inner>>,
    pub etw_active: Arc<AtomicBool>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// 解析 ETW QueryResults，例如 "type:  5 x.example.net;::ffff:1.2.3.4;2606:4700::1;"
fn parse_results(s: &str) -> (Vec<IpAddr>, Vec<String>) {
    let mut ips = Vec::new();
    let mut cnames = Vec::new();
    for part in s.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some(rest) = part.strip_prefix("type:") {
            let mut it = rest.split_whitespace();
            if it.next() == Some("5") {
                if let Some(n) = it.next() {
                    cnames.push(n.trim_end_matches('.').to_lowercase());
                }
            }
            continue;
        }
        let p = part.strip_prefix("::ffff:").unwrap_or(part);
        if let Ok(ip) = p.parse::<IpAddr>() {
            ips.push(ip);
        }
    }
    (ips, cnames)
}

impl Resolver {
    pub fn new(tls_probe: bool) -> Self {
        let r = Resolver::default();
        let me = r.clone();
        std::thread::spawn(move || me.ptr_worker());
        if tls_probe {
            let me = r.clone();
            std::thread::spawn(move || me.cert_worker());
        }
        r
    }

    fn observe(&self, ip: IpAddr, name: String, pid: Option<u32>) {
        let t = now();
        let mut g = self.inner.lock().unwrap();
        if let Some(pid) = pid {
            g.by_pid.entry((pid, ip)).or_default().insert(name.clone(), t);
        }
        g.names.entry(ip).or_default().insert(name, t);
    }

    /// 啟動 ETW DNS 監聽（需要管理員）。成功回傳 true。
    pub fn start_etw(&self) -> bool {
        use ferrisetw::parser::Parser;
        use ferrisetw::provider::Provider;
        use ferrisetw::schema_locator::SchemaLocator;
        use ferrisetw::trace::UserTrace;
        use ferrisetw::EventRecord;

        let me = self.clone();
        let cb = move |record: &EventRecord, loc: &SchemaLocator| {
            if record.event_id() != 3008 {
                return; // 3008 = 查詢完成
            }
            let Ok(schema) = loc.event_schema(record) else { return };
            let parser = Parser::create(record, &schema);
            let name: Option<String> = parser.try_parse("QueryName").ok();
            let results: Option<String> = parser.try_parse("QueryResults").ok();
            let (Some(name), Some(results)) = (name, results) else { return };
            let name = name.trim_end_matches('.').to_lowercase();
            if name.is_empty() {
                return;
            }
            let (ips, cnames) = parse_results(&results);
            let pid = record.process_id();
            {
                let mut g = me.inner.lock().unwrap();
                for c in cnames {
                    g.cname_parent.entry(c).or_insert_with(|| name.clone());
                }
            }
            for ip in ips {
                me.observe(ip, name.clone(), Some(pid));
            }
        };
        let provider = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d").add_callback(cb).build();
        // 固定的 session 名稱：上一次被強制結束時留下的 session 先停掉，避免累積（Windows 對即時 ETW session 數量有上限）
        let session = "RuoRuoWatchdog-DNS";
        let _ = ferrisetw::trace::stop_trace_by_name(session);
        match UserTrace::new().named(session.to_string()).enable(provider).start_and_process() {
            Ok(trace) => {
                self.etw_active.store(true, Ordering::SeqCst);
                // trace 被 drop 就會停止，所以讓它活到程式結束
                std::mem::forget(trace);
                true
            }
            Err(_) => false,
        }
    }

    /// 讀一次 Windows DNS 快取並併入對照表
    pub fn poll_cache(&self, wmi: &wmi::WMIConnection) {
        let rows: Vec<CacheEntry> = match wmi.raw_query("SELECT Entry, Data, Type FROM MSFT_DNSClientCache") {
            Ok(v) => v,
            Err(_) => return,
        };
        for e in rows {
            let (Some(entry), Some(data)) = (e.entry, e.data) else { continue };
            let entry = entry.trim_end_matches('.').to_lowercase();
            match e.kind {
                Some(1) | Some(28) => {
                    if let Ok(ip) = data.parse::<IpAddr>() {
                        self.observe(ip, entry, None);
                    }
                }
                Some(5) => {
                    let target = data.trim_end_matches('.').to_lowercase();
                    self.inner.lock().unwrap().cname_parent.insert(target, entry);
                }
                _ => {}
            }
        }
    }

    /// 這條連線可能對應的網域：先看這個程式自己查到的，再看全系統的，最後看憑證。
    pub fn domains(&self, pid: u32, ip: &IpAddr, port: u16, tls_probe: bool) -> (Vec<String>, Option<Source>) {
        let g = self.inner.lock().unwrap();
        let pick = |m: &HashMap<String, i64>| -> Vec<String> {
            let mut v: Vec<(&String, &i64)> = m.iter().collect();
            v.sort_by(|a, b| b.1.cmp(a.1));
            let mut out: Vec<String> = Vec::new();
            for (name, _) in v {
                let mut top = name.clone();
                let mut hops = 0;
                while let Some(p) = g.cname_parent.get(&top) {
                    top = p.clone();
                    hops += 1;
                    if hops > 8 {
                        break;
                    }
                }
                if !out.contains(&top) {
                    out.push(top);
                }
                if out.len() >= 5 {
                    break;
                }
            }
            out
        };
        if let Some(m) = g.by_pid.get(&(pid, *ip)) {
            return (pick(m), Some(Source::Etw));
        }
        if let Some(m) = g.names.get(ip) {
            let src = if self.etw_active.load(Ordering::Relaxed) { Source::Etw } else { Source::Cache };
            return (pick(m), Some(src));
        }
        if let Some(c) = g.cert.get(&(*ip, port)) {
            if !c.is_empty() {
                return (c.clone(), Some(Source::Cert));
            }
            return (vec![], None);
        }
        drop(g);
        if tls_probe && matches!(port, 443 | 8443) {
            let mut g = self.inner.lock().unwrap();
            if g.cert_pending.insert((*ip, port)) {
                g.cert_queue.push_back((*ip, port));
            }
        }
        (vec![], None)
    }

    /// PTR 反查結果；還沒查過就排進背景佇列，先回傳 None
    pub fn ptr(&self, ip: &IpAddr) -> Option<String> {
        let mut g = self.inner.lock().unwrap();
        if let Some(v) = g.ptr.get(ip) {
            return v.clone();
        }
        if g.ptr_pending.insert(*ip) {
            g.ptr_queue.push_back(*ip);
        }
        None
    }

    fn ptr_worker(&self) {
        loop {
            let next = self.inner.lock().unwrap().ptr_queue.pop_front();
            let Some(ip) = next else {
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            };
            let name = dns_lookup::lookup_addr(&ip).ok().filter(|n| n.parse::<IpAddr>().is_err());
            let mut g = self.inner.lock().unwrap();
            g.ptr.insert(ip, name);
            g.ptr_pending.remove(&ip);
        }
    }

    fn cert_worker(&self) {
        loop {
            let next = self.inner.lock().unwrap().cert_queue.pop_front();
            let Some((ip, port)) = next else {
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            };
            let names = crate::tlsname::cert_names(ip, port).unwrap_or_default();
            let mut g = self.inner.lock().unwrap();
            g.cert.insert((ip, port), names);
            g.cert_pending.remove(&(ip, port));
        }
    }
}

pub fn wmi_connection() -> Option<wmi::WMIConnection> {
    wmi::WMIConnection::with_namespace_path("ROOT\\StandardCimv2").ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_etw_results() {
        let (ips, cn) = parse_results("type:  5 edge.example.net;::ffff:1.2.3.4;2606:4700::6810:84e5;");
        assert_eq!(cn, vec!["edge.example.net"]);
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "1.2.3.4");
    }
}
