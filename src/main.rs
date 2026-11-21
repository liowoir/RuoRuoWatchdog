//! 若若看門狗 RuoRuoWatchdog — 監督這台 Windows 電腦上所有程式的對外連線。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ai;
mod asn;
mod config;
mod dns;
mod monitor;
mod net;
mod procinfo;
mod store;
mod tlsname;
mod web;

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use monitor::App;

const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_NAME: &str = "RuoRuoWatchdog";

fn open_browser(port: u16) {
    let _ = std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", &format!("http://127.0.0.1:{}/", port)]).spawn();
}

fn set_autostart(on: bool) -> bool {
    let exe = std::env::current_exe().unwrap_or_default();
    let status = if on {
        std::process::Command::new("reg")
            .args(["add", RUN_KEY, "/v", RUN_NAME, "/t", "REG_SZ", "/d", &format!("\"{}\" --background", exe.display()), "/f"])
            .status()
    } else {
        std::process::Command::new("reg").args(["delete", RUN_KEY, "/v", RUN_NAME, "/f"]).status()
    };
    status.map(|s| s.success()).unwrap_or(false)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let has = |f: &str| args.iter().any(|a| a == f);
    if has("--autostart-on") {
        std::process::exit(if set_autostart(true) { 0 } else { 1 });
    }
    if has("--autostart-off") {
        std::process::exit(if set_autostart(false) { 0 } else { 1 });
    }

    let dir = config::data_dir();
    let cfg = config::Config::load(&dir);
    cfg.save(&dir); // 第一次執行時寫出預設設定
    let port = cfg.port;
    let tls_probe = cfg.tls_probe;

    // 已經有一份在跑：直接打開儀表板就好
    let server = match tiny_http::Server::http(("127.0.0.1", port)) {
        Ok(s) => s,
        Err(_) => {
            if has("--open") || !has("--background") {
                open_browser(port);
            }
            return;
        }
    };

    let store = match store::Store::open(&dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("無法開啟資料庫：{e}");
            return;
        }
    };
    let app = Arc::new(App {
        dir: dir.clone(),
        cfg: Mutex::new(cfg),
        store: Mutex::new(store),
        resolver: dns::Resolver::new(tls_probe),
        asn: RwLock::new(None),
        live: Mutex::new(Default::default()),
        ai_status: Mutex::new("尚未執行".into()),
    });
    let etw = app.resolver.start_etw();
    app.store.lock().unwrap().event(
        "info",
        if etw {
            "若若看門狗啟動（管理員模式：可精確看到每個程式查詢的網域）"
        } else {
            "若若看門狗啟動（一般模式：網域來源靠 DNS 快取、憑證、反查；以管理員執行可更精確）"
        },
    );

    // ASN 資料庫在背景載入（檔案不小）
    {
        let a = app.clone();
        std::thread::spawn(move || {
            if let Some(db) = asn::AsnDb::load(&a.dir) {
                *a.asn.write().unwrap() = Some(db);
            }
        });
    }
    // 監控迴圈
    {
        let a = app.clone();
        std::thread::spawn(move || monitor::run(a));
    }
    // 自動 AI 分析（預設關閉）
    {
        let a = app.clone();
        std::thread::spawn(move || loop {
            let (on, mins) = {
                let c = a.cfg.lock().unwrap();
                (c.ai.auto_analyze && c.ai.provider != "none", c.ai.auto_interval_mins.max(5))
            };
            std::thread::sleep(Duration::from_secs(mins * 60));
            if on {
                ai::spawn(a.clone(), vec![], true);
            }
        });
    }

    if !has("--background") {
        open_browser(port);
    }
    web::serve(app, server, port);
}
