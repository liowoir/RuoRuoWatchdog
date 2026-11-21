//! IP → 自治系統（ASN）/ 所屬機構 / 國家。
//! 使用 iptoasn.com 的公開資料庫（ip2asn-combined.tsv.gz），下載到本機後離線查詢，
//! 查詢時不會把你的連線 IP 傳給任何第三方。

use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const DB_URL: &str = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";

#[derive(Clone, Debug, serde::Serialize)]
pub struct AsnInfo {
    pub asn: u32,
    pub country: String,
    pub org: String,
}

struct Range {
    start: u128,
    end: u128,
    info: usize,
}

pub struct AsnDb {
    ranges: Vec<Range>,
    infos: Vec<AsnInfo>,
}

fn key(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().into(),
        IpAddr::V6(v6) => (*v6).into(),
    }
}

impl AsnDb {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("ip2asn-combined.tsv.gz")
    }

    pub fn load(dir: &Path) -> Option<AsnDb> {
        let bytes = std::fs::read(Self::path(dir)).ok()?;
        let mut text = String::new();
        flate2::read::GzDecoder::new(&bytes[..]).read_to_string(&mut text).ok()?;
        let mut ranges = Vec::new();
        let mut infos: Vec<AsnInfo> = Vec::new();
        let mut index = std::collections::HashMap::<(u32, String, String), usize>::new();
        for line in text.lines() {
            let mut f = line.split('\t');
            let (Some(a), Some(b), Some(asn), Some(cc), Some(org)) = (f.next(), f.next(), f.next(), f.next(), f.next()) else { continue };
            let asn: u32 = asn.parse().unwrap_or(0);
            if asn == 0 {
                continue; // 未分配
            }
            let (Ok(a), Ok(b)) = (a.parse::<IpAddr>(), b.parse::<IpAddr>()) else { continue };
            let k = (asn, cc.to_string(), org.to_string());
            let id = *index.entry(k.clone()).or_insert_with(|| {
                infos.push(AsnInfo { asn: k.0, country: k.1, org: k.2 });
                infos.len() - 1
            });
            ranges.push(Range { start: key(&a), end: key(&b), info: id });
        }
        ranges.sort_by_key(|r| r.start);
        Some(AsnDb { ranges, infos })
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<AsnInfo> {
        let k = key(ip);
        let i = self.ranges.partition_point(|r| r.start <= k);
        if i == 0 {
            return None;
        }
        let r = &self.ranges[i - 1];
        (k <= r.end).then(|| self.infos[r.info].clone())
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }
}

/// 下載（或更新）資料庫，大約 11 MB
pub fn download(dir: &Path) -> anyhow::Result<()> {
    let mut resp = ureq::get(DB_URL).call()?;
    let bytes = resp.body_mut().with_config().limit(64 * 1024 * 1024).read_to_vec()?;
    let tmp = dir.join("ip2asn.download");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, AsnDb::path(dir))?;
    Ok(())
}
