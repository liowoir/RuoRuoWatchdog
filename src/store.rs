//! SQLite 歷史紀錄：每個「程式 + 遠端 IP + 埠」記一筆，另記程式第一次出現與事件。

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::Path;

pub struct Store {
    db: Connection,
}

#[derive(Serialize, Clone, Debug)]
pub struct Endpoint {
    pub id: i64,
    pub exe: String,
    pub proc_name: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub direction: String,
    pub domains: String,
    pub ptr: String,
    pub asn: String,
    pub org: String,
    pub country: String,
    pub signer: String,
    pub sig_status: String,
    pub flags: String,
    pub rule_risk: String,
    pub first_seen: String,
    pub last_seen: String,
    pub hits: i64,
    pub ai_risk: Option<String>,
    pub ai_reason: Option<String>,
    pub ai_at: Option<String>,
    pub domain_src: String,
    pub proto: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Event {
    pub id: i64,
    pub ts: String,
    pub level: String,
    pub message: String,
}

pub struct Upsert<'a> {
    pub proto: &'a str,
    pub exe: &'a str,
    pub proc_name: &'a str,
    pub remote_ip: &'a str,
    pub remote_port: u16,
    pub direction: &'a str,
    pub domains: &'a str,
    pub domain_src: &'a str,
    pub ptr: &'a str,
    pub asn: &'a str,
    pub org: &'a str,
    pub country: &'a str,
    pub signer: &'a str,
    pub sig_status: &'a str,
    pub flags: &'a str,
    pub rule_risk: &'a str,
}

fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

const ENDPOINTS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY, exe TEXT NOT NULL, proc_name TEXT, remote_ip TEXT NOT NULL, remote_port INTEGER NOT NULL,
    direction TEXT, domains TEXT, ptr TEXT, asn TEXT, org TEXT, country TEXT, signer TEXT, sig_status TEXT,
    flags TEXT, rule_risk TEXT, first_seen TEXT, last_seen TEXT, hits INTEGER DEFAULT 1,
    ai_risk TEXT, ai_reason TEXT, ai_at TEXT, domain_src TEXT, proto TEXT NOT NULL DEFAULT 'TCP',
    UNIQUE(exe, proto, remote_ip, remote_port));";

impl Store {
    pub fn open(dir: &Path) -> anyhow::Result<Store> {
        let db = Connection::open(dir.join("watchdog.db"))?;
        db.execute_batch("PRAGMA journal_mode=WAL;")?;
        // 舊版（0.1.x）的 endpoints 沒有 proto 欄位，而且唯一鍵不含協定，要重建資料表才能同時記 TCP 與 UDP
        let table_exists: bool = db.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='endpoints'", [], |r| r.get::<_, i64>(0)).map(|n| n > 0).unwrap_or(false);
        if table_exists {
            let _ = db.execute("ALTER TABLE endpoints ADD COLUMN domain_src TEXT", []);
            let has_proto: bool = db.query_row("SELECT COUNT(*) FROM pragma_table_info('endpoints') WHERE name='proto'", [], |r| r.get::<_, i64>(0)).map(|n| n > 0).unwrap_or(false);
            if !has_proto {
                db.execute_batch(&format!(
                    "BEGIN;
                     ALTER TABLE endpoints RENAME TO endpoints_old;
                     {ENDPOINTS_SCHEMA}
                     INSERT INTO endpoints (id, exe, proc_name, remote_ip, remote_port, direction, domains, ptr, asn, org, country, signer, sig_status, flags, rule_risk, first_seen, last_seen, hits, ai_risk, ai_reason, ai_at, domain_src, proto)
                       SELECT id, exe, proc_name, remote_ip, remote_port, direction, domains, ptr, asn, org, country, signer, sig_status, flags, rule_risk, first_seen, last_seen, hits, ai_risk, ai_reason, ai_at, domain_src, 'TCP' FROM endpoints_old;
                     DROP TABLE endpoints_old;
                     COMMIT;"
                ))?;
            }
        }
        db.execute_batch(&format!(
            "{ENDPOINTS_SCHEMA}
             CREATE TABLE IF NOT EXISTS programs (exe TEXT PRIMARY KEY, proc_name TEXT, first_seen TEXT, signer TEXT, sig_status TEXT);
             CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts TEXT, level TEXT, message TEXT);"
        ))?;
        Ok(Store { db })
    }

    pub fn program_count(&self) -> i64 {
        self.db.query_row("SELECT COUNT(*) FROM programs", [], |r| r.get(0)).unwrap_or(0)
    }

    /// 回傳 true 表示這是第一次看到這個程式
    pub fn touch_program(&self, exe: &str, name: &str, signer: &str, sig: &str) -> bool {
        let n = self
            .db
            .execute("INSERT OR IGNORE INTO programs (exe, proc_name, first_seen, signer, sig_status) VALUES (?1,?2,?3,?4,?5)", params![exe, name, now(), signer, sig])
            .unwrap_or(0);
        n > 0
    }

    /// 回傳 (id, 是否新的一筆)
    pub fn upsert(&self, u: &Upsert) -> (i64, bool) {
        let existing: Option<i64> = self
            .db
            .query_row("SELECT id FROM endpoints WHERE exe=?1 AND proto=?2 AND remote_ip=?3 AND remote_port=?4", params![u.exe, u.proto, u.remote_ip, u.remote_port], |r| r.get(0))
            .optional()
            .unwrap_or(None);
        let t = now();
        match existing {
            Some(id) => {
                // 網域只在有新資訊時覆寫，避免 DNS 快取過期後變空白
                let _ = self.db.execute(
                    "UPDATE endpoints SET last_seen=?1, hits=hits+1, proc_name=?2,
                       domains=CASE WHEN ?3<>'' THEN ?3 ELSE domains END,
                       domain_src=CASE WHEN ?3<>'' THEN ?12 ELSE domain_src END,
                       ptr=CASE WHEN ?4<>'' THEN ?4 ELSE ptr END,
                       asn=CASE WHEN ?5<>'' THEN ?5 ELSE asn END,
                       org=CASE WHEN ?6<>'' THEN ?6 ELSE org END,
                       country=CASE WHEN ?7<>'' THEN ?7 ELSE country END,
                       flags=?8, rule_risk=?9, direction=?10
                     WHERE id=?11",
                    params![t, u.proc_name, u.domains, u.ptr, u.asn, u.org, u.country, u.flags, u.rule_risk, u.direction, id, u.domain_src],
                );
                (id, false)
            }
            None => {
                let _ = self.db.execute(
                    "INSERT INTO endpoints (exe, proc_name, remote_ip, remote_port, direction, domains, ptr, asn, org, country, signer, sig_status, flags, rule_risk, first_seen, last_seen, domain_src, proto)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15,?16,?17)",
                    params![u.exe, u.proc_name, u.remote_ip, u.remote_port, u.direction, u.domains, u.ptr, u.asn, u.org, u.country, u.signer, u.sig_status, u.flags, u.rule_risk, t, u.domain_src, u.proto],
                );
                (self.db.last_insert_rowid(), true)
            }
        }
    }

    /// 同一次掃描內重複的連線：不加 hits，只取 id
    pub fn upsert_peek(&self, proto: &str, exe: &str, ip: &str, port: u16) -> i64 {
        self.db
            .query_row("SELECT id FROM endpoints WHERE exe=?1 AND proto=?2 AND remote_ip=?3 AND remote_port=?4", params![exe, proto, ip, port], |r| r.get(0))
            .unwrap_or(0)
    }

    /// 這筆紀錄目前在資料庫裡的內容（含上次查到的網域、擁有者與 AI 判斷）
    pub fn get(&self, id: i64) -> Option<Endpoint> {
        let sql = format!("SELECT {} FROM endpoints WHERE id=?1", Self::COLS);
        self.db.query_row(&sql, [id], Self::row).optional().unwrap_or(None)
    }

    pub fn set_ai(&self, id: i64, risk: &str, reason: &str) {
        let _ = self.db.execute("UPDATE endpoints SET ai_risk=?1, ai_reason=?2, ai_at=?3 WHERE id=?4", params![risk, reason, now(), id]);
    }

    pub fn event(&self, level: &str, msg: &str) {
        let _ = self.db.execute("INSERT INTO events (ts, level, message) VALUES (?1,?2,?3)", params![now(), level, msg]);
    }

    fn row(r: &rusqlite::Row) -> rusqlite::Result<Endpoint> {
        Ok(Endpoint {
            id: r.get(0)?,
            exe: r.get(1)?,
            proc_name: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            remote_ip: r.get(3)?,
            remote_port: r.get(4)?,
            direction: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            domains: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            ptr: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            asn: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
            org: r.get::<_, Option<String>>(9)?.unwrap_or_default(),
            country: r.get::<_, Option<String>>(10)?.unwrap_or_default(),
            signer: r.get::<_, Option<String>>(11)?.unwrap_or_default(),
            sig_status: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
            flags: r.get::<_, Option<String>>(13)?.unwrap_or_default(),
            rule_risk: r.get::<_, Option<String>>(14)?.unwrap_or_default(),
            first_seen: r.get::<_, Option<String>>(15)?.unwrap_or_default(),
            last_seen: r.get::<_, Option<String>>(16)?.unwrap_or_default(),
            hits: r.get(17)?,
            ai_risk: r.get(18)?,
            ai_reason: r.get(19)?,
            ai_at: r.get(20)?,
            domain_src: r.get::<_, Option<String>>(21)?.unwrap_or_default(),
            proto: r.get::<_, Option<String>>(22)?.unwrap_or_else(|| "TCP".into()),
        })
    }

    const COLS: &'static str = "id, exe, proc_name, remote_ip, remote_port, direction, domains, ptr, asn, org, country, signer, sig_status, flags, rule_risk, first_seen, last_seen, hits, ai_risk, ai_reason, ai_at, domain_src, proto";

    pub fn history(&self, limit: i64) -> Vec<Endpoint> {
        let sql = format!("SELECT {} FROM endpoints ORDER BY last_seen DESC LIMIT ?1", Self::COLS);
        let mut st = self.db.prepare(&sql).unwrap();
        st.query_map([limit], Self::row).unwrap().filter_map(Result::ok).collect()
    }

    /// 還沒給 AI 看過的紀錄（可疑的排前面）
    pub fn pending_ai(&self, limit: i64) -> Vec<Endpoint> {
        let sql = format!(
            "SELECT {} FROM endpoints WHERE ai_risk IS NULL
             ORDER BY CASE rule_risk WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, last_seen DESC LIMIT ?1",
            Self::COLS
        );
        let mut st = self.db.prepare(&sql).unwrap();
        st.query_map([limit], Self::row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn by_ids(&self, ids: &[i64]) -> Vec<Endpoint> {
        if ids.is_empty() {
            return vec![];
        }
        let list = ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        let sql = format!("SELECT {} FROM endpoints WHERE id IN ({})", Self::COLS, list);
        let mut st = self.db.prepare(&sql).unwrap();
        st.query_map([], Self::row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn events(&self, limit: i64) -> Vec<Event> {
        let mut st = self.db.prepare("SELECT id, ts, level, message FROM events ORDER BY id DESC LIMIT ?1").unwrap();
        st.query_map([limit], |r| Ok(Event { id: r.get(0)?, ts: r.get(1)?, level: r.get(2)?, message: r.get(3)? }))
            .unwrap()
            .filter_map(Result::ok)
            .collect()
    }
}
