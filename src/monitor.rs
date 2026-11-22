//! 監控主迴圈：每隔幾秒抓一次連線（TCP 連線 + UDP 流量）→ 補上程式 / 簽章 / 網域 / ASN → 套規則 → 寫進資料庫。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::asn::AsnDb;
use crate::config::Config;
use crate::dns::Resolver;
use crate::store::{Store, Upsert};
use crate::udp::UdpFlows;
use crate::{net, procinfo};

/// UDP 沒有連線狀態：最近這麼多秒內還有封包往來，就當作「目前的連線」
const UDP_LIVE_SECS: i64 = 30;

#[derive(Serialize, Clone, Debug)]
pub struct LiveRow {
    pub endpoint_id: i64,
    pub proto: String,
    pub pid: u32,
    pub proc_name: String,
    pub exe: String,
    pub services: Vec<String>,
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub state: String,
    pub direction: String,
    /// UDP 才有：這段期間送出 / 收到的位元組數
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub domains: Vec<String>,
    /// dns（程式自己查的）/ dns-cache / cert（憑證）/ 空白
    pub domain_src: String,
    pub ptr: String,
    pub asn: String,
    pub org: String,
    pub country: String,
    pub signer: String,
    pub sig_status: String,
    pub flags: Vec<String>,
    pub rule_risk: String,
    pub ai_risk: Option<String>,
    pub ai_reason: Option<String>,
}

/// 一個程式開著的 UDP 通訊埠
#[derive(Serialize, Clone, Debug)]
pub struct UdpSockRow {
    pub pid: u32,
    pub proc_name: String,
    pub exe: String,
    pub services: Vec<String>,
    pub local_port: u16,
    /// 所有網路介面 / 僅本機 / 指定位址
    pub scope: String,
    pub signer: String,
    pub sig_status: String,
    /// 目前和這個程式往來的外部 UDP 位址數（需要管理員模式才知道）
    pub flows: usize,
}

#[derive(Serialize, Clone, Default, Debug)]
pub struct Stats {
    pub total_tcp: usize,
    pub external: usize,
    pub udp_flows: usize,
    pub udp_ports: usize,
    pub programs: usize,
    pub unresolved: usize,
    pub last_scan: String,
    pub scan_ms: u128,
    pub asn_loaded: bool,
    pub dns_mode: String,
    /// "etw" = 看得到 UDP 往來的外部位址（管理員）；"ports" = 只知道哪些程式開了 UDP 埠
    pub udp_mode: String,
}

pub struct App {
    pub dir: std::path::PathBuf,
    pub cfg: Mutex<Config>,
    pub store: Mutex<Store>,
    pub resolver: Resolver,
    pub udp: UdpFlows,
    pub asn: RwLock<Option<AsnDb>>,
    pub live: Mutex<(Vec<LiveRow>, Stats)>,
    pub udp_ports: Mutex<Vec<UdpSockRow>>,
    pub ai_status: Mutex<String>,
}

const REMOTE_TOOLS: &[&str] = &[
    "anydesk", "teamviewer", "rustdesk", "duodesk", "screenconnect", "connectwise", "splashtop", "ultraviewer", "todesk",
    "sunloginclient", "awesun", "remotepc", "ammyy", "atera", "netsupport", "client32", "logmein", "radmin", "winvnc",
    "tvnserver", "vncserver", "parsecd", "remoting_host",
];

const COMMON_PORTS: &[u16] = &[
    80, 443, 53, 123, 853, 993, 995, 465, 587, 5222, 5223, 5228, 8443, 3478, 3479, 3480, 3481, 19302, 19305,
];

fn odd_path(p: &str) -> bool {
    let l = p.to_lowercase();
    ["\\temp\\", "\\tmp\\", "\\downloads\\", "\\desktop\\", "\\users\\public\\", "\\$recycle.bin\\", "\\perflogs\\"]
        .iter()
        .any(|s| l.contains(s))
        || (l.contains("\\appdata\\roaming\\") && l.matches('\\').count() <= 5)
        || (l.starts_with("c:\\programdata\\") && l.matches('\\').count() <= 2)
}

/// 規則判定：回傳 (旗標, 風險等級)。
/// UDP 不套用「少見埠」與「外部連入」：遊戲、語音、VPN、P2P 本來就用各種埠，而且 UDP 的「誰先送封包」不代表有人連進來。
fn rules(name: &str, exe: Option<&str>, sig: &str, proto: &str, port: u16, inbound: bool, new_program: bool) -> (Vec<String>, String) {
    let tcp = proto == "TCP";
    let mut f = Vec::new();
    let lname = name.to_lowercase();
    let remote_tool = REMOTE_TOOLS.iter().any(|t| lname.starts_with(t));
    // 瀏覽器幾乎只走 80/443，連到少見埠值得多看一眼
    let is_browser = ["chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "opera.exe", "vivaldi.exe"].contains(&lname.as_str());
    let inbound = inbound && tcp;
    if sig == "unsigned" {
        f.push("未簽章".to_string());
    }
    if sig == "invalid" {
        f.push("簽章無效".to_string());
    }
    if exe.map(odd_path).unwrap_or(false) {
        f.push("可疑位置".to_string());
    }
    if remote_tool {
        f.push("遠端控制工具".to_string());
    }
    if tcp && !COMMON_PORTS.contains(&port) && !(27000..=27100).contains(&port) && port < 49152 && !inbound {
        f.push(format!("少見埠{}", port));
    }
    if inbound {
        f.push("外部連入".to_string());
    }
    if new_program {
        f.push("新程式".to_string());
    }
    if exe.is_none() {
        f.push("路徑需管理員".to_string());
    }
    let has = |s: &str| f.iter().any(|x| x == s);
    let risk = if has("簽章無效") || (has("未簽章") && has("可疑位置")) || (inbound && remote_tool) || (inbound && has("未簽章")) {
        "high"
    } else if has("未簽章") || has("可疑位置") || remote_tool || inbound || (has("新程式") && sig != "valid") || (is_browser && f.iter().any(|x| x.starts_with("少見埠"))) {
        "medium"
    } else {
        "low"
    };
    (f, risk.to_string())
}

/// 這一輪要處理的一條「連線」：TCP 連線，或最近有往來的 UDP 流量
struct Item {
    proto: &'static str,
    pid: u32,
    remote_ip: IpAddr,
    remote_port: u16,
    local_port: u16,
    state: String,
    inbound: bool,
    sent: u64,
    recv: u64,
    /// 程式已經結束、掃描時查不到時，用事件當下記下的路徑
    fallback_path: Option<String>,
}

fn scope_of(ip: &IpAddr) -> &'static str {
    if ip.is_unspecified() {
        "所有網路介面"
    } else if ip.is_loopback() {
        "僅本機"
    } else {
        "指定位址"
    }
}

pub fn run(app: Arc<App>) {
    let Some(wmi) = crate::dns::wmi_connection() else {
        app.store.lock().unwrap().event("warn", "無法連上 WMI，網域解析只能用 PTR 反查");
        return run_inner(app, None);
    };
    run_inner(app, Some(wmi));
}

fn run_inner(app: Arc<App>, wmi: Option<wmi::WMIConnection>) {
    let mut baseline = app.store.lock().unwrap().program_count() == 0;
    if baseline {
        app.store.lock().unwrap().event("info", "第一次執行：目前會連外的程式都視為已知（不標「新程式」）");
    }
    let me = std::process::id();
    loop {
        let t0 = Instant::now();
        if let Some(w) = &wmi {
            app.resolver.poll_cache(w);
        }
        let procs = procinfo::snapshot();
        let conns = net::tcp_connections();
        let tls_probe = app.cfg.lock().unwrap().tls_probe;
        let listening: HashSet<u16> = conns.iter().filter(|c| c.state == "LISTEN").map(|c| c.local_port).collect();

        // ---- 組出這一輪的項目：TCP 連線 + UDP 流量 ----
        let mut items: Vec<Item> = conns
            .iter()
            .filter(|c| matches!(c.state, "ESTABLISHED" | "SYN_SENT" | "SYN_RCVD") && net::is_public(&c.remote_ip))
            .map(|c| Item {
                proto: "TCP",
                pid: c.pid,
                remote_ip: c.remote_ip,
                remote_port: c.remote_port,
                local_port: c.local_port,
                state: c.state.to_string(),
                inbound: listening.contains(&c.local_port) && c.state != "SYN_SENT",
                sent: 0,
                recv: 0,
                fallback_path: None,
            })
            .collect();
        let udp_etw = app.udp.active.load(std::sync::atomic::Ordering::Relaxed);
        if udp_etw {
            for f in app.udp.active_flows(UDP_LIVE_SECS) {
                items.push(Item {
                    proto: "UDP",
                    pid: f.pid,
                    remote_ip: f.remote_ip,
                    remote_port: f.remote_port,
                    local_port: f.local_port,
                    state: "ACTIVE".to_string(),
                    inbound: f.started_inbound,
                    sent: f.sent_bytes,
                    recv: f.recv_bytes,
                    fallback_path: f.exe_path.clone(),
                });
            }
        }

        let mut rows = Vec::new();
        let mut seen_keys = HashSet::new();
        let mut programs = HashSet::new();
        let mut unresolved = 0;
        let asn_guard = app.asn.read().unwrap();

        for c in items.iter() {
            if c.pid == me {
                continue;
            }
            let p = procs.get(&c.pid);
            let mut exe = p.and_then(|p| p.path.clone());
            let mut name = p.map(|p| p.name.clone());
            if p.is_none() {
                if let Some(path) = &c.fallback_path {
                    name = std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().to_string());
                    exe = Some(path.clone());
                }
            }
            let name = name.unwrap_or_else(|| format!("PID {}", c.pid));
            let exe_key = exe.clone().unwrap_or_else(|| name.clone());
            let sig = exe.as_deref().map(procinfo::signature);
            let (sig_status, signer) = match &sig {
                Some(s) => (s.status.clone(), s.signer.clone().unwrap_or_default()),
                None => ("unknown".to_string(), String::new()),
            };
            // UDP 沒有「誰連誰」：只依實際收發的資料量描述（監聽開始前就存在的流量，第一個看到的封包方向不可靠）
            let direction = if c.proto == "UDP" {
                match (c.sent > 0, c.recv > 0) {
                    (true, true) => "雙向",
                    (true, false) => "只送出",
                    (false, true) => "只收到",
                    _ => "—",
                }
            } else if c.inbound {
                "連入"
            } else {
                "連出"
            };

            let (domains, dsrc) = app.resolver.domains(c.pid, &c.remote_ip, c.remote_port, tls_probe);
            let domain_src = match dsrc {
                Some(crate::dns::Source::Etw) => "dns",
                Some(crate::dns::Source::Cache) => "dns-cache",
                Some(crate::dns::Source::Cert) => "cert",
                None => "",
            };
            let ptr = app.resolver.ptr(&c.remote_ip).unwrap_or_default();
            let asn = asn_guard.as_ref().and_then(|d| d.lookup(&c.remote_ip));

            let store = app.store.lock().unwrap();
            let new_program = store.touch_program(&exe_key, &name, &signer, &sig_status) && !baseline;
            if new_program {
                store.event(
                    "new",
                    &format!("新程式第一次連外：{} → {}:{}（{}）  簽章：{}", name, c.remote_ip, c.remote_port, c.proto, if signer.is_empty() { sig_status.as_str() } else { signer.as_str() }),
                );
            }
            let (flags, rule_risk) = rules(&name, exe.as_deref(), &sig_status, c.proto, c.remote_port, c.inbound, new_program);
            let ip = c.remote_ip.to_string();
            let key = (c.proto, exe_key.clone(), ip.clone(), c.remote_port);
            let first_in_scan = seen_keys.insert(key);
            let (id, is_new) = if first_in_scan {
                store.upsert(&Upsert {
                    proto: c.proto,
                    exe: &exe_key,
                    proc_name: &name,
                    remote_ip: &ip,
                    remote_port: c.remote_port,
                    direction,
                    domains: &domains.join(", "),
                    domain_src,
                    ptr: &ptr,
                    asn: &asn.as_ref().map(|a| format!("AS{}", a.asn)).unwrap_or_default(),
                    org: &asn.as_ref().map(|a| a.org.clone()).unwrap_or_default(),
                    country: &asn.as_ref().map(|a| a.country.clone()).unwrap_or_default(),
                    signer: &signer,
                    sig_status: &sig_status,
                    flags: &flags.join(" "),
                    rule_risk: &rule_risk,
                })
            } else {
                (store.upsert_peek(c.proto, &exe_key, &ip, c.remote_port), false)
            };
            if is_new && rule_risk == "high" {
                store.event("warn", &format!("高風險連線：{} → {}:{}（{}）  [{}]", name, ip, c.remote_port, c.proto, flags.join(" ")));
            }
            // 這次掃描沒查到的欄位，沿用資料庫裡上次查到的（例如剛重啟、DNS 紀錄已過期）
            let saved = store.get(id);
            drop(store);
            let (mut domains, mut domain_src, mut ptr) = (domains, domain_src.to_string(), ptr);
            let (mut asn_s, mut org, mut country) = match &asn {
                Some(a) => (format!("AS{}", a.asn), a.org.clone(), a.country.clone()),
                None => (String::new(), String::new(), String::new()),
            };
            let (mut ai_risk, mut ai_reason) = (None, None);
            if let Some(s) = saved {
                if domains.is_empty() && !s.domains.is_empty() {
                    domains = s.domains.split(", ").map(String::from).collect();
                    domain_src = s.domain_src;
                }
                if ptr.is_empty() {
                    ptr = s.ptr;
                }
                if org.is_empty() {
                    (asn_s, org, country) = (s.asn, s.org, s.country);
                }
                (ai_risk, ai_reason) = (s.ai_risk, s.ai_reason);
            }
            if domains.is_empty() && ptr.is_empty() {
                unresolved += 1;
            }

            programs.insert(exe_key.clone());
            rows.push(LiveRow {
                endpoint_id: id,
                proto: c.proto.to_string(),
                pid: c.pid,
                proc_name: name,
                exe: exe.unwrap_or_default(),
                services: p.map(|p| p.services.clone()).unwrap_or_default(),
                remote_ip: ip,
                remote_port: c.remote_port,
                local_port: c.local_port,
                state: c.state.clone(),
                direction: direction.to_string(),
                sent_bytes: c.sent,
                recv_bytes: c.recv,
                domains,
                domain_src,
                ptr,
                asn: asn_s,
                org,
                country,
                signer,
                sig_status,
                flags,
                rule_risk,
                ai_risk,
                ai_reason,
            });
        }
        drop(asn_guard);
        baseline = false;

        // ---- UDP 通訊埠清單（不需要管理員）----
        let mut flows_by_pid: HashMap<u32, usize> = HashMap::new();
        for r in rows.iter().filter(|r| r.proto == "UDP") {
            *flows_by_pid.entry(r.pid).or_default() += 1;
        }
        let mut seen_ports = HashSet::new();
        let mut udp_rows: Vec<UdpSockRow> = Vec::new();
        for s in net::udp_sockets() {
            if s.pid == me || s.pid == 0 || !seen_ports.insert((s.pid, s.local_port)) {
                continue; // IPv4 與 IPv6 各會有一筆，合併成一筆
            }
            let p = procs.get(&s.pid);
            let exe = p.and_then(|p| p.path.clone());
            let sig = exe.as_deref().map(procinfo::signature);
            udp_rows.push(UdpSockRow {
                pid: s.pid,
                proc_name: p.map(|p| p.name.clone()).unwrap_or_else(|| format!("PID {}", s.pid)),
                exe: exe.unwrap_or_default(),
                services: p.map(|p| p.services.clone()).unwrap_or_default(),
                local_port: s.local_port,
                scope: scope_of(&s.local_ip).to_string(),
                signer: sig.as_ref().and_then(|s| s.signer.clone()).unwrap_or_default(),
                sig_status: sig.map(|s| s.status).unwrap_or_else(|| "unknown".into()),
                flows: flows_by_pid.get(&s.pid).copied().unwrap_or(0),
            });
        }
        // 範圍最大的排前面（所有網路介面 → 指定位址 → 僅本機），同範圍內有往來的優先
        let scope_rank = |s: &str| match s {
            "所有網路介面" => 0,
            "指定位址" => 1,
            _ => 2,
        };
        udp_rows.sort_by(|a, b| scope_rank(&a.scope).cmp(&scope_rank(&b.scope)).then(b.flows.cmp(&a.flows)).then(a.proc_name.cmp(&b.proc_name)).then(a.local_port.cmp(&b.local_port)));
        let udp_ports = udp_rows.len();
        *app.udp_ports.lock().unwrap() = udp_rows;

        let stats = Stats {
            total_tcp: conns.len(),
            external: rows.iter().filter(|r| r.proto == "TCP").count(),
            udp_flows: rows.iter().filter(|r| r.proto == "UDP").count(),
            udp_ports,
            programs: programs.len(),
            unresolved,
            last_scan: chrono::Local::now().format("%H:%M:%S").to_string(),
            scan_ms: t0.elapsed().as_millis(),
            asn_loaded: app.asn.read().unwrap().is_some(),
            dns_mode: if app.resolver.etw_active.load(std::sync::atomic::Ordering::Relaxed) { "etw".into() } else { "basic".into() },
            udp_mode: if udp_etw { "etw".into() } else { "ports".into() },
        };
        *app.live.lock().unwrap() = (rows, stats);

        let secs = app.cfg.lock().unwrap().interval_secs.max(2);
        std::thread::sleep(Duration::from_secs(secs));
    }
}
