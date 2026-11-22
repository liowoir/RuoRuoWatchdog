//! 本機儀表板：只綁 127.0.0.1，檢查 Host 標頭防 DNS rebinding，
//! 會改變狀態的 POST 需要自訂標頭 X-Watchdog（跨站網頁無法偷偷送出）。

use std::io::Read;
use std::sync::Arc;

use serde_json::json;
use tiny_http::{Header, Method, Request, Response, Server};

use crate::config::Config;
use crate::monitor::App;

const INDEX: &str = include_str!("../web/index.html");

fn header(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap()
}

fn send_json(req: Request, v: serde_json::Value, code: u16) {
    let r = Response::from_string(v.to_string())
        .with_status_code(code)
        .with_header(header("Content-Type", "application/json; charset=utf-8"))
        .with_header(header("Cache-Control", "no-store"));
    let _ = req.respond(r);
}

fn host_ok(req: &Request, port: u16) -> bool {
    let host = req.headers().iter().find(|h| h.field.equiv("Host")).map(|h| h.value.as_str().to_string()).unwrap_or_default();
    host == format!("127.0.0.1:{}", port) || host == format!("localhost:{}", port)
}

fn has_token(req: &Request) -> bool {
    req.headers().iter().any(|h| h.field.equiv("X-Watchdog") && h.value.as_str() == "1")
}

pub fn serve(app: Arc<App>, server: Server, port: u16) {
    for mut req in server.incoming_requests() {
        if !host_ok(&req, port) {
            let _ = req.respond(Response::from_string("forbidden").with_status_code(403));
            continue;
        }
        let url = req.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        let method = req.method().clone();
        if method == Method::Post && !has_token(&req) {
            let _ = req.respond(Response::from_string("missing token").with_status_code(403));
            continue;
        }
        let mut body = String::new();
        if method == Method::Post {
            let _ = req.as_reader().take(1 << 20).read_to_string(&mut body);
        }
        let body_json: serde_json::Value = serde_json::from_str(&body).unwrap_or(json!({}));

        match (method, path.as_str()) {
            (Method::Get, "/") => {
                let r = Response::from_string(INDEX)
                    .with_header(header("Content-Type", "text/html; charset=utf-8"))
                    .with_header(header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'"));
                let _ = req.respond(r);
            }
            (Method::Get, "/api/live") => {
                let (rows, stats) = app.live.lock().unwrap().clone();
                let ai = app.ai_status.lock().unwrap().clone();
                send_json(req, json!({"rows": rows, "stats": stats, "ai_status": ai}), 200);
            }
            (Method::Get, "/api/udp-ports") => {
                let rows = app.udp_ports.lock().unwrap().clone();
                let mode = app.live.lock().unwrap().1.udp_mode.clone();
                send_json(req, json!({"rows": rows, "udp_mode": mode}), 200);
            }
            (Method::Get, "/api/history") => {
                let rows = app.store.lock().unwrap().history(2000);
                send_json(req, json!({"rows": rows}), 200);
            }
            (Method::Get, "/api/events") => {
                let ev = app.store.lock().unwrap().events(300);
                send_json(req, json!({"events": ev}), 200);
            }
            (Method::Get, "/api/config") => {
                let mut c = app.cfg.lock().unwrap().clone();
                let has_key = c.api_key().is_some();
                c.ai.api_key = String::new();
                send_json(req, json!({"config": c, "has_key": has_key}), 200);
            }
            (Method::Post, "/api/config") => {
                let mut cur = app.cfg.lock().unwrap().clone();
                if let Ok(mut new) = serde_json::from_value::<Config>(body_json.clone()) {
                    // 空白金鑰代表「不更改」
                    if new.ai.api_key.trim().is_empty() {
                        new.ai.api_key = cur.ai.api_key.clone();
                    }
                    new.port = cur.port; // 埠號改了要重啟，這裡不動
                    cur = new;
                    cur.save(&app.dir);
                    *app.cfg.lock().unwrap() = cur;
                    send_json(req, json!({"ok": true}), 200);
                } else {
                    send_json(req, json!({"ok": false, "error": "設定格式錯誤"}), 400);
                }
            }
            (Method::Post, "/api/analyze") => {
                let ids: Vec<i64> = body_json["ids"].as_array().map(|a| a.iter().filter_map(|v| v.as_i64()).collect()).unwrap_or_default();
                let only = body_json["only_suspicious"].as_bool().unwrap_or(false);
                let started = crate::ai::spawn(app.clone(), ids, only);
                send_json(req, json!({"started": started}), 200);
            }
            (Method::Post, "/api/asn/download") => {
                let a = app.clone();
                std::thread::spawn(move || {
                    let msg = match crate::asn::download(&a.dir) {
                        Ok(()) => match crate::asn::AsnDb::load(&a.dir) {
                            Some(db) => {
                                let n = db.len();
                                *a.asn.write().unwrap() = Some(db);
                                format!("ASN 資料庫已更新（{} 個網段）", n)
                            }
                            None => "ASN 資料庫下載了但讀不進來".into(),
                        },
                        Err(e) => format!("ASN 資料庫下載失敗：{}", e),
                    };
                    a.store.lock().unwrap().event("info", &msg);
                });
                send_json(req, json!({"started": true}), 200);
            }
            _ => {
                let _ = req.respond(Response::from_string("not found").with_status_code(404));
            }
        }
    }
}
