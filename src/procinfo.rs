//! 程序資訊：名稱、執行檔路徑、數位簽章、svchost 內含的服務名稱。

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
    WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::{GUID, PCWSTR, PWSTR};

#[derive(Clone, Debug, serde::Serialize)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub services: Vec<String>,
}

fn wstr(buf: &[u16]) -> String {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..n])
}

/// 一次取得所有程序（名稱、路徑、服務）
pub fn snapshot() -> HashMap<u32, ProcInfo> {
    let mut map = HashMap::new();
    unsafe {
        if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
            if Process32FirstW(snap, &mut e).is_ok() {
                loop {
                    let pid = e.th32ProcessID;
                    map.insert(pid, ProcInfo { pid, name: wstr(&e.szExeFile), path: image_path(pid), services: vec![] });
                    if Process32NextW(snap, &mut e).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }
    }
    for (pid, svc) in services_by_pid() {
        if let Some(p) = map.get_mut(&pid) {
            p.services.push(svc);
        }
    }
    map
}

fn image_path(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let r = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(h);
        r.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

fn services_by_pid() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) else { return out };
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        let _ = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, None, &mut needed, &mut count, Some(&mut resume), PCWSTR::null());
        let mut buf = vec![0u8; needed as usize + 1024];
        resume = 0;
        if EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, Some(&mut buf), &mut needed, &mut count, Some(&mut resume), PCWSTR::null()).is_ok() {
            let items = std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
            for it in items {
                let pid = it.ServiceStatusProcess.dwProcessId;
                if pid != 0 {
                    out.push((pid, it.lpServiceName.to_string().unwrap_or_default()));
                }
            }
        }
        let _ = CloseServiceHandle(scm);
    }
    out
}

/// 數位簽章結果
#[derive(Clone, Debug, serde::Serialize)]
pub struct Signature {
    /// "valid" / "unsigned" / "invalid" / "system"（Windows 目錄簽章，無內嵌簽章）
    pub status: String,
    pub signer: Option<String>,
}

static SIG_CACHE: Mutex<Option<HashMap<String, Signature>>> = Mutex::new(None);

pub fn signature(path: &str) -> Signature {
    let key = path.to_lowercase();
    if let Some(s) = SIG_CACHE.lock().unwrap().get_or_insert_with(HashMap::new).get(&key) {
        return s.clone();
    }
    let s = verify(path);
    SIG_CACHE.lock().unwrap().get_or_insert_with(HashMap::new).insert(key, s.clone());
    s
}

fn verify(path: &str) -> Signature {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let r = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut c_void);

        let mut signer = None;
        if r == 0 {
            let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
            if !prov.is_null() {
                let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
                if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                    let cert = (*(*sgnr).pasCertChain).pCert;
                    let mut buf = [0u16; 256];
                    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
                    if n > 1 {
                        signer = Some(String::from_utf16_lossy(&buf[..(n - 1) as usize]));
                    }
                }
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut c_void);

        let lower = path.to_lowercase();
        let status = match r as u32 {
            0 => "valid",
            0x800B0100 => {
                // TRUST_E_NOSIGNATURE：Windows 內建檔多半走目錄簽章，這裡不額外驗證，只標記為系統位置
                if lower.starts_with(r"c:\windows\") || lower.contains(r"\windowsapps\") { "system" } else { "unsigned" }
            }
            _ => "invalid",
        };
        Signature { status: status.into(), signer }
    }
}
