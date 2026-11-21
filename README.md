# 若若看門狗 RuoRuoWatchdog

監督 Windows 電腦上**每一個程式的對外連線**：誰在連、連到哪個網域、對方是哪家機構、程式有沒有數位簽章。也可以請 AI 逐筆判斷可不可疑。

不跳通知、不打擾。所有紀錄都留在本機，打開瀏覽器裡的儀表板（`http://127.0.0.1:8765`）就能看。

## 功能

- **即時連線列表**：每 5 秒掃描一次所有 TCP 連線（IPv4 / IPv6），列出程式名稱、執行檔路徑、svchost 內的服務名稱、遠端 IP 與埠、連出或連入。
- **網域來源解析**（依可信度排序）：
  1. **程式自己查詢的網域**：以管理員執行時，即時監聽 Windows DNS 查詢事件（ETW `Microsoft-Windows-DNS-Client`），知道「哪個程式查了哪個網域、得到哪個 IP」。
  2. **Windows DNS 快取**：一般權限即可讀取。
  3. **HTTPS 憑證**：查不到 DNS 時，對遠端做一次 TLS 握手，讀憑證上登記的網域。只握手，不送任何資料；可在設定中關閉。
  4. **PTR 反查**。
- **網路擁有者**：用 [iptoasn.com](https://iptoasn.com) 的公開資料庫，在本機離線查出 ASN、機構與國家。不會把你的連線 IP 送去第三方查詢。
- **數位簽章**：驗證每個執行檔的 Authenticode 簽章，並讀出簽章者。
- **規則標記**：未簽章、簽章無效、放在暫存或下載資料夾等可疑位置、遠端控制工具（AnyDesk、TeamViewer、RustDesk…）、少見埠、外部連入、第一次出現的新程式。
- **AI 分析**（可選，可以用訂閱或 API 金鑰）：
  - `claude-cli`：用你已登入的 [Claude Code](https://claude.com/claude-code)（Claude 訂閱），呼叫 `claude -p`。
  - `codex-cli`：用你已登入的 Codex CLI（ChatGPT 訂閱），呼叫 `codex exec`。
  - `anthropic-api`：用 Anthropic API 金鑰，預設模型 `claude-opus-5-5`，並使用結構化輸出。
  - 可以手動對單筆「問 AI」、一次分析所有可疑連線，或設定定時自動分析。
- **歷史紀錄與事件**：SQLite 保存每個「程式 + 遠端 IP + 埠」第一次和最後一次出現的時間與次數，以及新程式、高風險連線、AI 判定為高風險等事件。

## 安裝與執行

1. 從 [Releases](../../releases) 下載 `ruoruo-watchdog.exe`，或自己編譯（見下方）。
2. 直接執行。程式會在背景啟動，並自動打開儀表板。再執行一次只會再打開儀表板，不會重複啟動。
3. 到「設定」頁按「下載 / 更新 ASN 資料庫」（約 11 MB），就能看到每個 IP 屬於哪家機構。

### 命令列參數

| 參數 | 作用 |
|---|---|
| `--background` | 只在背景執行，不自動打開瀏覽器 |
| `--autostart-on` | 登入 Windows 時自動在背景啟動（寫入目前使用者的 Run 機碼，不需要管理員） |
| `--autostart-off` | 取消自動啟動 |

### 管理員模式（實驗性，尚未完整驗證）

一般權限下，有些服務程式的路徑讀不到，網域也只能靠 DNS 快取、憑證和反查來推測。用管理員身分執行時，會改為監聽 DNS 查詢事件，可以精確知道每個程式查了哪些網域。

想要開機就以管理員身分執行，可以用「工作排程器」建立一個登入時觸發、勾選「以最高權限執行」的工作，動作設為 `ruoruo-watchdog.exe --background`。

## 資料與隱私

- 所有資料都放在 `%APPDATA%\RuoRuoWatchdog\`：`watchdog.db`（紀錄）、`config.json`（設定與 API 金鑰）、ASN 資料庫。
- 儀表板只綁定 `127.0.0.1`，並檢查 Host 標頭；會改變狀態的請求必須帶自訂標頭，其他網站無法替你操作。
- 只有在你啟用 AI 分析時，連線摘要才會傳給你選的 AI 服務。內容包含程式名稱、路徑、簽章、遠端 IP、網域、機構和規則標記。路徑中的使用者資料夾預設會換成 `%USERPROFILE%`。

## 已知限制

- 瀏覽器若開了「安全 DNS（DNS over HTTPS）」會自己解析網域，不經過 Windows，這類連線常常只能看到 IP 和網路擁有者。Cloudflare 之類共用 IP 的 CDN，不帶 SNI 也讀不到憑證。
- AI 分析三種方式中，目前只有 `claude-cli` 實際跑過完整流程；`codex-cli` 與 `anthropic-api` 已實作但尚未實測。
- 目前只監看 TCP。UDP（例如 QUIC / HTTP3、遊戲語音）還沒有列入。
- 有些系統的 Windows DNS 快取讀出來是空的，這時請改用管理員模式。

## 自己編譯

需要 Rust 1.85 以上（edition 2024），以及 Windows 上的 MSVC 工具鏈。

```powershell
cargo build --release
```

執行檔在 `target\release\ruoruo-watchdog.exe`。

## 授權

MIT
