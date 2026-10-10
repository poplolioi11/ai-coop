# 來源與公開整理範圍

專案發起與原創整理：[poplolioi11](https://github.com/poplolioi11)。本庫維持 MIT 授權，著作權聲明見 [LICENSE](LICENSE)；散布副本或實質部分時須保留該署名與授權聲明。

AI Coop 是為有界的本機多模型協作編寫的 Python 參考實作，結合通用 MCP 介面、官方命令列入口與主代理操作指引。公開版由獨立的原始碼副本整理，沒有匯入私人安裝目錄、既有 Git 歷史、任務資料或帳戶設定。

公開整理包括通用路徑設定、原始碼與執行資料分離、合成的 agent／hook 測試材料、最小操作範例，以及逐檔發布白名單與校驗。原始碼編寫、整理與獨立覆核使用了 AI 助手；測試與內容檢查由程式執行。AI 輸出仍需審閱，不能視為來源、正確性或安全性的第三方認證。

## 公開內容

- 架構程式、命令列入口與 MCP 介面。
- 通用 Skill 與權限設定生成助手。
- 自行建立的合成測試、通用範例與說明。
- SHA-256 檔案清單與離線發布檢查器。

未納入登入資料、私人任務、私人使用者輸入、真實模型回傳、歷史對話、個人路徑、帳戶方案、價格、餘額或用量。公開的作者識別僅使用已指定的 GitHub 帳號 poplolioi11。測試中的假帳密值與 session／job 識別碼均為合成 fixture，不對應真實帳戶或既有工作。

## 上游技術依據

只連接使用者自行安裝的上游程式，不重新散布它們或模型權重。

- [Model Context Protocol 架構與規格](https://modelcontextprotocol.io/docs/learn/architecture)
- [Claude Code 程式化使用](https://code.claude.com/docs/en/headless)
- [Google Antigravity headless 模式](https://antigravity.google/docs/cli/headless/)
- [Google Antigravity 原生權限](https://antigravity.google/docs/permissions?tab=cli)
- [Codex CLI 開源實作](https://github.com/openai/codex)
- [Ollama Chat API](https://docs.ollama.com/api/chat)
- [Ollama 執行程式](https://github.com/ollama/ollama)
- [Qwen 本機模型套件](https://ollama.com/library/qwen3.5:9b-q4_K_M)

本庫沒有複製上述專案的來源檔案。其名稱用於辨識連接對象，不表示官方合作或背書。上游的授權、模型條件與服務條件請向各自來源查閱。

## 可驗證的主張

`SHA256SUMS` 與 `verify_release.py` 確認公開版本的檔案集合及完整性；合成測試覆蓋任務協調、設定、工具守門與本機服務清理的行為。這些檢查不能替代其他電腦上的安裝驗收、真實模型往返或完整安全審計。

變更程式、測試或文件時，需先審閱內容，再同步更新校驗清單；不能只修改校驗值來掩蓋未解釋的差異。
