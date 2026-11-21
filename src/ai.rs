//! AI 分析：把一批連線摘要交給 AI 判斷風險。
//! - claude-cli：用已登入的 Claude Code（訂閱），`claude -p`
//! - codex-cli：用已登入的 Codex CLI（ChatGPT 訂閱），`codex exec`
//! - anthropic-api：直接呼叫 Anthropic Messages API（需要 API 金鑰）

use std::io::Write;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;

use crate::monitor::App;
use crate::store::Endpoint;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const BATCH: usize = 40;

#[derive(Deserialize, Debug)]
struct Verdict {
    id: i64,
    risk: String,
    reason: String,
}

#[derive(Deserialize, Debug)]
struct Verdicts {
    results: Vec<Verdict>,
}

fn redact(path: &str, on: bool) -> String {
    if !on {
        return path.to_string();
    }
    match std::env::var("USERPROFILE") {
        Ok(home) if !home.is_empty() && path.to_lowercase().starts_with(&home.to_lowercase()) => {
            format!("%USERPROFILE%{}", &path[home.len()..])
        }
        _ => path.to_string(),
    }
}

fn prompt(items: &[Endpoint], redact_paths: bool) -> String {
    let list: Vec<_> = items
        .iter()
        .map(|e| {
            json!({
                "id": e.id,
                "program": e.proc_name,
                "path": redact(&e.exe, redact_paths),
                "signature": if e.signer.is_empty() { e.sig_status.clone() } else { format!("{} ({})", e.signer, e.sig_status) },
                "remote": format!("{}:{}", e.remote_ip, e.remote_port),
                "direction": e.direction,
                "domains_from_dns_cache": e.domains,
                "reverse_dns": e.ptr,
                "network_owner": format!("{} {} {}", e.asn, e.org, e.country).trim().to_string(),
                "rule_flags": e.flags,
                "first_seen": e.first_seen,
                "times_seen": e.hits,
            })
        })
        .collect();
    format!(
        "你是 Windows 電腦的資安分析員。下面是這台電腦上程式對外的 TCP 連線紀錄（JSON）。\n\
         請逐筆判斷這條連線是否可疑，考慮：程式是否為知名軟體、數位簽章、執行檔位置、連到的網域與網路擁有者是否符合該程式的用途、埠號、是否為外部連入、遠端控制工具等。\n\
         - 網域欄位空白代表無法從 DNS 快取得知（例如瀏覽器使用安全 DNS），不要單憑這點判定可疑。\n\
         - 瀏覽器（chrome/edge/brave/firefox）連到各種網站是正常的，除非埠號或網路擁有者很不尋常。\n\
         risk 只能是 safe / low / medium / high。reason 用繁體中文一兩句話，說明這是什麼服務、為何這樣判斷；high 時說明建議的處理方式。\n\
         只輸出 JSON，格式：{{\"results\":[{{\"id\":數字,\"risk\":\"...\",\"reason\":\"...\"}}]}}，每一筆都要有。\n\n連線資料：\n{}",
        serde_json::to_string_pretty(&list).unwrap_or_default()
    )
}

fn extract_json(text: &str) -> anyhow::Result<Verdicts> {
    let s = text.find('{').ok_or_else(|| anyhow::anyhow!("AI 回覆裡沒有 JSON"))?;
    let e = text.rfind('}').ok_or_else(|| anyhow::anyhow!("AI 回覆裡沒有 JSON"))?;
    Ok(serde_json::from_str(&text[s..=e])?)
}

fn run_cli(program: &str, args: &[&str], input: &str, cwd: &std::path::Path) -> anyhow::Result<String> {
    // npm 安裝的 claude / codex 是 .cmd 包裝，所以經由 cmd /C 執行
    let mut cmd = Command::new("cmd");
    cmd.arg("/C").arg(program).args(args).current_dir(cwd).creation_flags(CREATE_NO_WINDOW);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    child.stdin.take().unwrap().write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() && stdout.trim().is_empty() {
        anyhow::bail!("{} 執行失敗：{}", program, String::from_utf8_lossy(&out.stderr).chars().take(300).collect::<String>());
    }
    Ok(stdout)
}

fn ask_claude_cli(p: &str, dir: &std::path::Path) -> anyhow::Result<Verdicts> {
    let out = run_cli("claude", &["-p", "--output-format", "text"], p, dir)?;
    extract_json(&out)
}

fn ask_codex_cli(p: &str, dir: &std::path::Path) -> anyhow::Result<Verdicts> {
    let last = dir.join("codex-last-message.txt");
    let _ = std::fs::remove_file(&last);
    let last_s = last.to_string_lossy().to_string();
    let out = run_cli("codex", &["exec", "--skip-git-repo-check", "--sandbox", "read-only", "-o", &last_s, "-"], p, dir)?;
    let text = std::fs::read_to_string(&last).unwrap_or(out);
    extract_json(&text)
}

fn ask_api(p: &str, key: &str, model: &str) -> anyhow::Result<Verdicts> {
    let schema = json!({
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "risk": {"type": "string", "enum": ["safe", "low", "medium", "high"]},
                        "reason": {"type": "string"}
                    },
                    "required": ["id", "risk", "reason"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["results"],
        "additionalProperties": false
    });
    let body = json!({
        "model": model,
        "max_tokens": 16000,
        "output_config": {"effort": "low", "format": {"type": "json_schema", "schema": schema}},
        "fallbacks": "default",
        "messages": [{"role": "user", "content": p}]
    });
    let resp: serde_json::Value = ureq::post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key)
        .header("anthropic-version", "2026-10-21")
        .header("anthropic-beta", "server-side-fallback-2026-07-01")
        .header("content-type", "application/json")
        .config()
        .http_status_as_error(false)
        .build()
        .send_json(&body)?
        .body_mut()
        .read_json()?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("API 錯誤：{}", err.get("message").and_then(|m| m.as_str()).unwrap_or("未知"));
    }
    if resp["stop_reason"] == "refusal" {
        anyhow::bail!("模型拒絕回答這批資料");
    }
    let text: String = resp["content"]
        .as_array()
        .map(|a| a.iter().filter(|b| b["type"] == "text").filter_map(|b| b["text"].as_str()).collect())
        .unwrap_or_default();
    extract_json(&text)
}

/// 分析指定的紀錄（ids 為空時分析尚未分析過的，可疑的優先），回傳處理筆數
pub fn analyze(app: &Arc<App>, ids: Vec<i64>, only_suspicious: bool) -> anyhow::Result<usize> {
    let cfg = app.cfg.lock().unwrap().clone();
    let mut items = {
        let s = app.store.lock().unwrap();
        if ids.is_empty() { s.pending_ai(200) } else { s.by_ids(&ids) }
    };
    if only_suspicious {
        items.retain(|e| e.rule_risk != "low");
    }
    if items.is_empty() {
        return Ok(0);
    }
    let mut done = 0;
    for chunk in items.chunks(BATCH) {
        *app.ai_status.lock().unwrap() = format!("分析中… {}/{}（{}）", done, items.len(), cfg.ai.provider);
        let p = prompt(chunk, cfg.ai.redact_paths);
        let v = match cfg.ai.provider.as_str() {
            "claude-cli" => ask_claude_cli(&p, &app.dir)?,
            "codex-cli" => ask_codex_cli(&p, &app.dir)?,
            "anthropic-api" => {
                let key = cfg.api_key().ok_or_else(|| anyhow::anyhow!("沒有設定 API 金鑰（設定頁或環境變數 ANTHROPIC_API_KEY）"))?;
                ask_api(&p, &key, &cfg.ai.model)?
            }
            other => anyhow::bail!("AI 未啟用（provider = {}）", other),
        };
        let valid: std::collections::HashSet<i64> = chunk.iter().map(|e| e.id).collect();
        let s = app.store.lock().unwrap();
        for r in v.results.into_iter().filter(|r| valid.contains(&r.id)) {
            let risk = match r.risk.as_str() {
                "safe" | "low" | "medium" | "high" => r.risk.clone(),
                _ => "medium".into(),
            };
            if risk == "high" {
                s.event("ai", &format!("AI 判定高風險（#{}）：{}", r.id, r.reason));
            }
            s.set_ai(r.id, &risk, &r.reason);
            done += 1;
        }
    }
    Ok(done)
}

/// 背景執行分析，狀態寫進 app.ai_status
pub fn spawn(app: Arc<App>, ids: Vec<i64>, only_suspicious: bool) -> bool {
    {
        let st = app.ai_status.lock().unwrap();
        if st.starts_with("分析中") {
            return false;
        }
    }
    *app.ai_status.lock().unwrap() = "分析中…".into();
    std::thread::spawn(move || {
        let msg = match analyze(&app, ids, only_suspicious) {
            Ok(0) => "沒有需要分析的連線".to_string(),
            Ok(n) => format!("完成：分析了 {} 筆（{}）", n, chrono::Local::now().format("%H:%M")),
            Err(e) => format!("失敗：{}", e),
        };
        *app.ai_status.lock().unwrap() = msg;
    });
    true
}
