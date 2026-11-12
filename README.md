# HideTheKey (`hide-the-key`)

GitHubへのAPIキー、秘密鍵、機密設定ファイルの漏洩を未然に防止するセキュリティ監査ツール。  
ローカル環境における `.gitignore` カバレッジ検証、静的コード解析、および CI/CD パイプライン連携に対応。

[![macOS supported](https://img.shields.io/badge/macOS-Supported-brightgreen.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Python3%20Only-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

---

## 1. 概要

HideTheKey は、Gitリポジトリおよびローカルファイルシステムを走査し、機密情報の混入や不適切な構成管理を検出・修正するセキュリティ監査エンジンである。  
従来のシークレットスキャナーが検知対象外としていた「コミット前の `.gitignore` 除外漏れ」を水際で捕捉するとともに、外部ライブラリに依存しないゼロディペンデンシー設計（macOS/Linux標準の Python 3 および Git のみ）を採用している。

### 主要機能
1. **機密設定ファイルの検出および `.gitignore` カバレッジ監査**  
   `.env`, `credentials.json`, `*.pem`, `*.key` 等の存在を走査し、Git管理対象（Tracked/Staged）に含まれていないか、および `.gitignore` に明示的に定義されているかを判定。
2. **静的コード解析による認証情報およびトークン検出**  
   OpenAI, Anthropic, Google Gemini, AWS, GitHub, Stripe 等の主要クラウドプロバイダ固有のトークン構造、および高エントロピー文字列を検出。
3. **危険なコード参照パターンの検出**  
   フロントエンド環境変数（`NEXT_PUBLIC_`, `VITE_` 等）によるブラウザへの秘密鍵露出、環境変数取得時のフォールバック値への直接記述、ログ出力へのトークン受け渡しを検出。
4. **履歴走査および不要ファイル監査**  
   過去のコミット履歴（`--history`）の監査、および `.DS_Store` や SQLite データベースファイル等のリポジトリ混入防止。
5. **自動修復機能 (`--fix`)**  
   未登録ファイルの `.gitignore` への自動追記、およびインデックス登録済みファイルに対する `git rm --cached` の安全な適用。

---

## 2. 既存ツールとの比較および技術的優位性

| 評価項目 | HideTheKey | Gitleaks | TruffleHog | GitGuardian |
| :--- | :---: | :---: | :---: | :---: |
| **`.gitignore` カバレッジ監査** | **対応** (未コミット時の除外漏れを防止) | 非対応 (コミット差分のみ) | 非対応 (コミット差分のみ) | 非対応 (コミット差分のみ) |
| **自動修復機能 (`--fix`)** | **対応** (`.gitignore` 追記・インデックス除外) | 非対応 | 非対応 | 非対応 |
| **マルチリポジトリ横断監査** | **対応** (PC内リポジトリ自動発見・集計) | 非対応 (単一リポジトリ単位) | 非対応 (単一リポジトリ単位) | 非対応 |
| **外部依存性** | **不要** (標準Python 3およびGitのみ) | 要バイナリ導入 (Go) | 要バイナリ導入 (Go) | 要アカウント登録・APIキー発行 |
| **スタンドアローン HTML レポート** | **標準装備** (外部通信不要) | 非対応 | 非対応 | Webダッシュボード連携 |
| **Git pre-commit フック導入** | **単一コマンドで生成** (`--install-hook`) | 手動構成が必要 | 手動構成が必要 | 導入コマンドあり |
| **GitHub Actions / SARIF 連携** | **対応** (Code Scanning / PRアノテーション) | 対応 | 対応 | 対応 |
| **AIエージェント向け Skill 統合** | **対応** (`SKILL.md` 付属) | 非対応 | 非対応 | 非対応 |

### 技術的特徴
- **水際対策の徹底**: コミット差分のみを検査する既存ツールに対し、ローカル環境の未追跡ファイルが意図せず `git add .` 等でコミットされるリスクを構造的に排除する。
- **データローカリティの保証**: コードやトークンを外部サーバーへ送信せず、完全にローカル環境内で解析を完結させる。

---

## 3. 検出仕様

### 3.1 機密設定ファイル
- 環境変数定義ファイル: `.env`, `.env.local`, `.env.production` 等
- 秘密鍵および証明書: `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.pkcs12`, `*.keystore`
- サービスアカウントおよび認証ファイル: `serviceAccountKey*.json`, `client_secret*.json`, `credentials.json`, `firebase*.json`
- ネットワークおよび認証情報: `.netrc`, `.htpasswd`  
*※ `.env.example`, `.env.sample`, `*.template` 等の公開前提ファイルは自動識別により除外される。*

### 3.2 認証トークンおよび API キー
- **OpenAI**: `sk-[a-zA-Z0-9]{48}`, `sk-proj-[a-zA-Z0-9_\-]{20,}`, `sk-admin-...`
- **Anthropic Claude**: `sk-ant-(?:api03|admin01)-[a-zA-Z0-9_\-]{32,}`
- **Google / Gemini**: `AIzaSy[0-9A-Za-z_\-]{33}`
- **AWS**: `(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}` (Access Key ID)
- **GitHub**: `ghp_...` (Personal Access Token), `github_pat_...` (Fine-grained), `gho_...`, `ghs_...`
- **Slack**: `xoxb-...`, `xoxp-...`, Webhook URL
- **Stripe**: `sk_live_...`, `rk_live_...`
- **その他**: Discord Bot Token, Telegram Bot Token, HuggingFace Token (`hf_...`), Groq, Resend, Supabase, SendGrid, Twilio, NPM/PyPI トークン, RSA/EC 秘密鍵ヘッダーブロック

### 3.3 危険なコード参照パターン (Code Patterns)
- **公開環境変数への秘密鍵代入**: `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` 等のプレフィックスを伴う秘密情報参照（ブラウザのJavaScriptバンドルへの混入防止）。
- **環境変数フォールバックへの直書き**: `process.env.KEY || "raw_secret"` や `os.getenv("KEY", "raw_secret")` 等のデフォルト値混入。
- **URL内への直接埋め込み**: URLクエリパラメータ (`?key=...`) または Basic 認証形式 (`https://user:token@host`) によるクレデンシャル露出。
- **ログ出力へのトークン受け渡し**: `console.log(process.env.KEY)` や `print(secret_key)` 等の出力処理。
- **コンテナ定義内の平文指定**: Dockerfile の `ENV` や `ARG` 命令における秘密鍵指定。

### 3.4 リポジトリ混入不適格ファイル
- macOS 固有メタデータ: `.DS_Store`, `.AppleDouble`
- データベースファイル: `*.sqlite`, `*.sqlite3`, `*.db`, `*.sql.gz`, `*.dump`

---

## 4. 判定基準 (Severity Levels)

| レベル | 状態 | 影響および対策 |
| :--- | :--- | :--- |
| **CRITICAL** | Git追跡中 / ステージング中 | 既にGit管理下にあり、プッシュ時にGitHubへ漏洩する状態。`git rm --cached` の実行およびキーの即時失効・再発行が必要。 |
| **HIGH** | 未追跡かつ `.gitignore` 未除外 | 機密ファイルが存在するが除外設定が欠如している状態。`--fix` による `.gitignore` への追記が必要。 |
| **MEDIUM** | Git管理外ディレクトリでの検知 | Git非管理フォルダ内に存在する機密情報。将来的なリポジトリ化の際に注意を要する。 |
| **LOW** | 除外設定済みファイル内のキー | ファイル自体は `.gitignore` で保護されているが、平文キーが含まれる状態。 |
| **SAFE** | 保護完了 | 機密ファイルが存在するが、`.gitignore` のルールにより安全に除外されている状態。 |

---

## 5. 使用方法

### 5.1 CLI による実行
```bash
# カレントディレクトリの監査
./bin/hide-the-key

# 対象ディレクトリを指定した監査
./bin/hide-the-key /path/to/project

# パソコン全体（ホームディレクトリ配下の全リポジトリ）の横断監査
./bin/hide-the-key --global

# コミット履歴を含めた全量監査
./bin/hide-the-key --history

# 未登録シークレットの自動除外およびキャッシュ解除
./bin/hide-the-key --fix

# 機械可読形式での出力 (CI/CD 連携用)
./bin/hide-the-key --json

# SARIF v2.1.0 形式での出力 (GitHub Code Scanning 連携用)
./bin/hide-the-key --sarif results.sarif
```

### 5.2 システムへのインストール
```bash
./install.sh
```
`~/.local/bin/hide-the-key` にシンボリックリンクが生成され、任意のパスから実行可能となる。

### 5.3 macOS GUI ランチャー
`hide-the-key.command` を実行することで、対話型ターミナルが起動する。ドラッグ＆ドロップによるフォルダ指定スキャン、またはホームディレクトリ全体の監査を選択可能。

---

## 6. パイプラインおよび開発環境連携

### 6.1 Git pre-commit フックの導入
コミット実行時に自動検証を行い、違反が検出された場合にコミット処理を中止する。
```bash
hide-the-key --install-hook
```
対象リポジトリの `.git/hooks/pre-commit` が自動生成される。

### 6.2 GitHub Actions 連携
リポジトリのルートで以下のコマンドを実行し、ワークフロー定義を生成する。
```bash
hide-the-key --init-ci
```
生成される定義ファイル (`.github/workflows/hide-the-key.yml`) により、以下のイベントが自動監査される：
- 全ブランチおよびタグへのプッシュ
- Pull Request（変更行へのインラインアノテーション出力）
- 深夜定期実行（Cronスケジュールによるコミット履歴監査）
- 手動トリガー (`workflow_dispatch`)
- GitHub Security タブ（Code scanning alerts）への SARIF アップロード

### 6.3 GitLab CI 連携
```bash
hide-the-key --init-gitlab
```
`.gitlab-ci.yml` が生成され、GitLab の Secret Detection レポートと統合される。

### 6.4 AI エージェント向け Skill 統合
本リポジトリには `skills/hide-the-key/SKILL.md` が同梱されている。  
Antigravity, Claude Code, Gemini CLI 等の自律エージェントにおいて、コード変更完了後かつプッシュ前のゲートキーパーとして呼び出し可能である。

---

## 7. コマンドライン引数リファレンス

```
usage: hide-the-key [-h] [--global] [--root ROOT] [--history] [--fix] [--json]
                    [--ci] [--sarif FILE] [--install-hook] [--init-ci]
                    [--init-gitlab] [--html [HTML]] [--no-open] [--interactive]
                    [path]

positional arguments:
  path                  スキャン対象のパス（省略時はカレントリポジトリまたはホームディレクトリ）

options:
  -h, --help            ヘルプメッセージを表示して終了
  --global, -g          ホームディレクトリ配下の全リポジトリを横断スキャン
  --root ROOT           グローバルスキャンの起点ディレクトリを指定（デフォルト: '~'）
  --history             Gitコミット履歴を走査し過去の機密混入を検査
  --fix                 未除外の機密ファイルを .gitignore に追記しインデックスから解除
  --json                解析結果を JSON 形式で出力
  --ci                  CI実行モード（GitHub Actions 向けアノテーションおよびサマリー出力）
  --sarif FILE          解析結果を SARIF v2.1.0 形式で出力
  --install-hook        対象リポジトリに Git pre-commit フックをインストール
  --init-ci             GitHub Actions ワークフロー定義ファイルを生成
  --init-gitlab         GitLab CI パイプライン定義ファイルを生成
  --html [HTML]         スタンドアローン HTML レポートを生成（デフォルト: hide-the-key-report.html）
  --no-open             HTML レポート生成後のブラウザ自動起動を抑止
  --interactive         対話型プロンプトモードで実行
```

---

## 8. テスト

```bash
python3 -m unittest discover -s tests
```

---

## 9. ライセンス

本ソフトウェアは MIT License の下で公開されている。詳細は [LICENSE](LICENSE) ファイルを参照のこと。
