# 🗝️ HideTheKey (`hide-the-key`)

> **GitHubへのAPIキー・機密ファイルの誤プッシュを未然に防ぐ、高速・高精度なセキュリティ監査CLI＆GUIランチャーツール**

[![macOS supported](https://img.shields.io/badge/macOS-Supported-brightgreen.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Python3%20Only-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

---

## 📌 概要

`HideTheKey` は、指定したディレクトリやGitリポジトリを瞬時にスキャンし、以下を自動点検・保護するツールです：

1. **機密ファイルの検知 & `.gitignore` カバレッジ検査**
   - `.env`, `.env.production`, `*.pem`, `*.key`, `serviceAccountKey*.json` などの機密ファイルが存在するか。
   - それらが `.gitignore` でしっかりと除外されているか。
   - **すでに Git のステージングやコミットで追跡対象になってしまっていないか**（最重要）。
2. **コード内にハードコードされた API キー・シークレットの検出**
   - OpenAI, Anthropic (Claude), Google Gemini, AWS, GitHub PAT, Slack, Stripe, Discord, HuggingFace, 秘密鍵 などの主要サービスキーをコードから自動検出。
   - 画面出力時はキーの中央部を自動マスク（`sk-proj-abc...****...xyz`）し、端末や画面共有時の安全を確保。
3. **GitHubに上げるべきでない不要・危険ファイルの検出**
   - `.DS_Store`（Macのメタ情報）、SQLiteデータベース（`*.sqlite3`, `*.db`）、DBダンプファイルなど。
4. **過去のコミット履歴の検査 (`--history`)**
   - 過去のコミットで誤って `.env` や鍵を上げてしまっていないかを履歴から追跡。
5. **ワンクリック/ワンコマンド自動修正 (`--fix`)**
   - 見落としていた機密ファイルを `.gitignore` に自動追加。
   - すでにインデックスに追加されていた場合は `git rm --cached` で追跡を解除。

---

## 🚀 3つの使い方

### ① Mac Finder からダブルクリックで使う (`.command`)
ターミナルコマンドが苦手な場合や、素早くフォルダを点検したい場合に最適です。

1. `hide-the-key.command` を Finder でダブルクリックします。
2. ターミナルウィンドウが立ち上がり、**「点検したいフォルダをドラッグ＆ドロップ（またはEnterで現在のフォルダ）」** と聞かれます。
3. フォルダをウィンドウ内にドラッグ＆ドロップして `Enter` を押すだけで、瞬時に診断結果が表示されます。
4. 未登録の `.env` がある場合、その場で `y` を押せば `.gitignore` への自動追加も完了します。

---

### ② ターミナルから CLI ツールとして使う
プロジェクト直下から直接コマンドを実行できます。

```bash
# カレントディレクトリをスキャン
./bin/hide-the-key

# 特定のプロジェクトディレクトリを指定してスキャン
./bin/hide-the-key ~/my-web-app

# 開発フォルダ配下の全Gitリポジトリを一括スキャン
./bin/hide-the-key ~/Projects --all

# 過去のコミット履歴も含めて漏洩を点検
./bin/hide-the-key --history

# 未登録のシークレットを自動で .gitignore に追加・追跡解除
./bin/hide-the-key --fix

# CI/CD パイプライン連携用の JSON 出力
./bin/hide-the-key --json
```

---

### ③ グローバルコマンドとしてインストールする (`install.sh`)
どのディレクトリからでも `hide-the-key` と打つだけで実行できるようにします。

```bash
./install.sh
```

`~/.local/bin/hide-the-key` にシンボリックリンクが作成されます。  
（`~/.zshrc` などに `export PATH="$HOME/.local/bin:$PATH"` が追加されていれば、どこからでも `hide-the-key` が呼べるようになります）

---

## 🥊 既存ツールとの比較・圧倒的な差別化ポイント

世の中には `Gitleaks`, `TruffleHog`, `GitGuardian (ggshield)` などのシークレットスキャナーが存在しますが、**HideTheKey は既存ツールの最大の弱点である「.gitignoreカバレッジの盲点」「導入の面倒さ」「マシン全体の把握難」を完全に解消**しています。

| 比較項目 | **HideTheKey** (本ツール) | **Gitleaks** | **TruffleHog** | **GitGuardian** |
| :--- | :---: | :---: | :---: | :---: |
| **`.gitignore` カバレッジ監査** | **◎ (.envの除外漏れを未然検知)** | ✕ (コミット差分のみ) | ✕ (コミット差分のみ) | ✕ (コミット差分のみ) |
| **ワンコマンド自動修復 (`--fix`)** | **◎ (.gitignore追記 & rm --cached)** | ✕ (検出のみ) | ✕ (検出のみ) | ✕ (検出のみ) |
| **パソコン全体 (100+リポジトリ) 監査** | **◎ (全リポジトリ自動発見 & 集計)** | ✕ (1リポジトリ単位) | ✕ (1リポジトリ単位) | ✕ (個別設定) |
| **外部依存 / アカウント登録** | **ゼロ (macOS標準Python3のみ)** | △ (Goバイナリの導入要) | △ (Goバイナリの導入要) | ✕ (SaaS登録 & APIキー必須) |
| **Mac GUI & インタラクティブHTML** | **◎ (.command + ブラウザHTML)** | ✕ (CUIテキストのみ) | ✕ (CUIテキストのみ) | △ (SaaS画面) |
| **Git pre-commit ワンタッチ導入** | **◎ (`--install-hook` で1秒)** | △ (手動スクリプト作成) | △ (手動設定要) | ○ (`ggshield install`) |
| **GitHub Actions PR インライン警告** | **◎ (`::error` でFiles changedに表示)** | ○ (設定が必要) | ○ (設定が必要) | ○ |
| **AIエージェント (Skill) ネイティブ対応**| **◎ (`SKILL.md` 完備)** | ✕ (人間向けのみ) | ✕ (人間向けのみ) | ✕ (人間向けのみ) |

### HideTheKey ならではのコア強み：
1. **「差分スキャン」だけでなく「.gitignore 漏れ」を水際で防ぐ**:  
   Gitleaks等は「すでにコミットされたテキスト」しか見ません。HideTheKeyは「まだコミットしていないがローカルにある `.env` が `.gitignore` に書かれていない（次の `git add .` で誤って上がってしまう）」状態を警告・自動修正します。
2. **完全ローカル完結＆ゼロ依存**:  
   SaaSにコードやシークレットを送信するリスクが一切なく、追加の `pip install` や Go バイナリも不要。
3. **AI コーディングエージェントの安全装置 (Skill)**:  
   Antigravity, Claude Code, Gemini CLI などのAIがコードを生成・編集した後、自律的に安全点検を行い、問題があれば自動修正してからプッシュする「AI時代のためのガードレール」として機能します。

---

### 1. 機密設定・シークレットファイル
- `.env`, `.env.local`, `.env.development`, `.env.production` など
- `id_rsa`, `id_ed25519`, `id_ecdsa` (SSH秘密鍵)
- `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.pkcs12`, `*.keystore`
- `serviceAccountKey*.json`, `client_secret*.json`, `credentials.json`, `firebase*.json`
- `.netrc`, `.htpasswd`
- ※ `.env.example`, `.env.sample`, `*.template` などの安全なテンプレートファイルは自動判定して除外します。

### 2. コード内のハードコードされた API キー / トークン
- **OpenAI**: `sk-...`, `sk-proj-...`, `sk-admin-...`
- **Anthropic Claude**: `sk-ant-api03-...`, `sk-ant-admin01-...`
- **Google / Gemini**: `AIzaSy...`
- **AWS**: `AKIA...`, `ASIA...` (Access Key ID)
- **GitHub**: `ghp_...` (PAT), `github_pat_...` (Fine-grained), `gho_...`, `ghs_...`
- **Slack**: `xoxb-...`, `xoxp-...`, Webhook URL
- **Stripe**: `sk_live_...`, `rk_live_...`
- **その他**: Discord Bot, Telegram Bot, HuggingFace (`hf_...`), Groq, Resend, Supabase, SendGrid, Twilio, NPM/PyPI トークン, RSA/EC 秘密鍵ヘッダー, 汎用APIキー代入式

### 3. その他 GitHub に不要・危険なファイル
- `.DS_Store` (Macのフォルダ属性メタデータ)
- `*.sqlite`, `*.sqlite3`, `*.db` (ローカルDB)
- `*.sql.gz`, `*.dump` (データベースダンプ)

---

## 🚦 判定レベル（Severity）

| レベル | アイコン | 状態 | 影響と対策 |
| :--- | :---: | :--- | :--- |
| **CRITICAL** | 🚨 | **Git 追跡中 / ステージング中** | **すでに GitHub に上がる状態です！** `git rm --cached` を実行し、キーをローテーションしてください。 |
| **HIGH** | ⚠️ | **未登録の機密ファイル** | `.env` 等が存在しますが `.gitignore` にありません。`git add .` で誤って上がります。`--fix` で除外してください。 |
| **MEDIUM** | ⚡ | **Git管理外の機密情報** | Gitリポジトリ外のファイルにキーが存在します。リポジトリ化の際に注意が必要です。 |
| **LOW** | ℹ️ | **gitignore除外済みコード内のキー** | ファイル自体は除外されていますが、コード内に平文キーが存在します。 |
| **SAFE** | ✅ | **保護済み** | 機密ファイルが存在しますが、`.gitignore` のルールにより安全に除外されています。 |

---

## 🤖 CI/CD・Gitフック・AIエージェントへの組み込み

### 1. Git pre-commit フックのワンタッチ導入
現在のプロジェクトでコミット時に自動スキャンし、シークレットがあればコミットをブロックします：
```bash
hide-the-key --install-hook
```

### 2. GitHub Actions ワークフローの一発生成
リポジトリに `.github/workflows/hide-the-key.yml` を自動生成します：
```bash
hide-the-key --init-ci
```
PR作成時やプッシュ時にCIが走り、GitHub の PR 画面（Files changed）上にインラインで直接赤く警告（Annotation）が表示されます。

### 3. AIエージェント（Antigravity / Claude Code）の Skill として利用
本リポジトリには [skills/hide-the-key/SKILL.md](skills/hide-the-key/SKILL.md) が同梱されています。  
AIエージェントに「コミット前に hide-the-key でシークレットと .gitignore をチェックして」と指示するだけで、自律的に安全点検＆修正を行わせることができます。

---

## ⚙️ コマンドライン引数一覧

```
usage: hide-the-key [-h] [--all] [--history] [--fix] [--json] [--no-safe] [--interactive] [path]

positional arguments:
  path           スキャン対象ディレクトリのパス (省略時はカレントディレクトリ)

options:
  -h, --help     ヘルプメッセージを表示
  --all          指定ディレクトリ配下のすべてのGitリポジトリを再帰的にスキャン
  --history      直近のGitコミット履歴を走査し、過去にコミットされた機密ファイルを検出
  --fix          未除外の機密ファイルを .gitignore に自動追加し、キャッシュを解除
  --json         結果を JSON 形式で標準出力 (CI/CD連携用)
  --no-safe      安全に除外されている (.gitignore済み) ファイルの表示を省略
  --interactive  対話モードで実行 (Finderからのドラッグ＆ドロップ対応)
```

---

## 🧪 テストの実行

```bash
python3 -m unittest discover -s tests
```

---

## 📄 ライセンス

MIT License
