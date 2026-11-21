//! 監控主迴圈：每隔幾秒抓一次連線 → 補上程式 / 簽章 / 網域 / ASN → 套規則 → 寫進資料庫。

use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::asn::AsnDb;
use crate::config::Config;
use crate::dns::Resolver;
use crate::store::{Store, Upsert};
use crate::{net, procinfo};

#[derive(Serialize, Clone, Debug)]
pub struct LiveRow {
    pub endpoint_id: i64,
    pub pid: u32,
    pub proc_name: String,
    pub exe: String,
    pub services: Vec<String>,
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub state: String,
    pub direction: String,
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

#[derive(Serialize, Clone, Default, Debug)]
pub struct Stats {
    pub total_tcp: usize,
    pub external: usize,
    pub programs: usize,
    pub unresolved: usize,
    pub last_scan: String,
    pub scan_ms: u128,
    pub asn_loaded: bool,
    pub dns_mode: String,
}

pub struct App {
    pub dir: std::path::PathBuf,
    pub cfg: Mutex<Config>,
    pub store: Mutex<Store>,
    pub resolver: Resolver,
    pub asn: RwLock<Option<AsnDb>>,
    pub live: Mutex<(Vec<LiveRow>, Stats)>,
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

/// 規則判定：回傳 (旗標, 風險等級)
fn rules(name: &str, exe: Option<&str>, sig: &str, port: u16, inbound: bool, new_program: bool) -> (Vec<String>, String) {
    let mut f = Vec::new();
    let lname = name.to_lowercase();
    let remote_tool = REMOTE_TOOLS.iter().any(|t| lname.starts_with(t));
    // 瀏覽器幾乎只走 80/443，連到少見埠值得多看一眼
    let is_browser = ["chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "opera.exe", "vivaldi.exe"].contains(&lname.as_str());
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
    if !COMMON_PORTS.contains(&port) && !(27000..=27100).contains(&port) && port < 49152 && !inbound {
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

        let mut rows = Vec::new();
        let mut seen_keys = HashSet::new();
        let mut programs = HashSet::new();
        let mut unresolved = 0;
        let asn_guard = app.asn.read().unwrap();

        for c in conns.iter().filter(|c| matches!(c.state, "ESTABLISHED" | "SYN_SENT" | "SYN_RCVD") && net::is_public(&c.remote_ip)) {
            if c.pid == me {
                continue;
            }
            let p = procs.get(&c.pid);
            let name = p.map(|p| p.name.clone()).unwrap_or_else(|| format!("PID {}", c.pid));
            let exe = p.and_then(|p| p.path.clone());
            let exe_key = exe.clone().unwrap_or_else(|| name.clone());
            let sig = exe.as_deref().map(procinfo::signature);
            let (sig_status, signer) = match &sig {
                Some(s) => (s.status.clone(), s.signer.clone().unwrap_or_default()),
                None => ("unknown".to_string(), String::new()),
            };
            let inbound = listening.contains(&c.local_port) && c.state != "SYN_SENT";
            let direction = if inbound { "連入" } else { "連出" };

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
                store.event("new", &format!("新程式第一次連外：{} → {}:{}  簽章：{}", name, c.remote_ip, c.remote_port, if signer.is_empty() { sig_status.as_str() } else { signer.as_str() }));
            }
            let (flags, rule_risk) = rules(&name, exe.as_deref(), &sig_status, c.remote_port, inbound, new_program);
            let ip = c.remote_ip.to_string();
            let key = (exe_key.clone(), ip.clone(), c.remote_port);
            let first_in_scan = seen_keys.insert(key);
            let (id, is_new) = if first_in_scan {
                store.upsert(&Upsert {
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
                (store.upsert_peek(&exe_key, &ip, c.remote_port), false)
            };
            if is_new && rule_risk == "high" {
                store.event("warn", &format!("高風險連線：{} → {}:{}  [{}]", name, ip, c.remote_port, flags.join(" ")));
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
                pid: c.pid,
                proc_name: name,
                exe: exe.unwrap_or_default(),
                services: p.map(|p| p.services.clone()).unwrap_or_default(),
                remote_ip: ip,
                remote_port: c.remote_port,
                local_port: c.local_port,
                state: c.state.to_string(),
                direction: direction.to_string(),
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

        let stats = Stats {
            total_tcp: conns.len(),
            external: rows.len(),
            programs: programs.len(),
            unresolved,
            last_scan: chrono::Local::now().format("%H:%M:%S").to_string(),
            scan_ms: t0.elapsed().as_millis(),
            asn_loaded: app.asn.read().unwrap().is_some(),
            dns_mode: if app.resolver.etw_active.load(std::sync::atomic::Ordering::Relaxed) { "etw".into() } else { "basic".into() },
        };
        *app.live.lock().unwrap() = (rows, stats);

        let secs = app.cfg.lock().unwrap().interval_secs.max(2);
        std::thread::sleep(Duration::from_secs(secs));
    }
}
