# SimplyNote.vim

[SimplyNote](https://github.com/iz69/SimplyNote) を Vim / Neovim から操作するためのプラグインです。
一覧と本文の2ペインで、ノートの閲覧・作成・編集・削除を行えます。

<img src="https://github.com/user-attachments/assets/eeb41852-6d84-40a1-ba92-8e06f5c01caa" width="450" alt="SimplyNote.vim の画面" />

## 主な機能

- ノート一覧と本文プレビューの2ペイン表示
- ノートの作成・編集・保存・削除
- トークン認証と、期限切れ時の自動再ログイン
- タグ、スター、添付ファイル数、更新日時の一覧表示
- 添付ファイルのリンク表示とブラウザ起動
- `trash` タグ付きノートの一覧からの除外
- 一覧にフォーカスしたまま本文をスクロール
- 未保存の編集内容を自動プレビューで上書きしない保護

## 必要環境

- Python 3 サポートが有効な Vim / Neovim
- 接続可能な SimplyNote サーバー

Python 3 サポートは `:echo has('python3')` で確認できます。`1` が表示されれば利用できます。

## インストール

利用中のプラグインマネージャーに `iz69/SimplyNote_vim` を追加してください。

vim-plug の例:

```vim
Plug 'iz69/SimplyNote_vim'
```

インストール後、必要に応じて `:helptags ALL` を実行します。

## 設定

`vimrc` または `init.vim` に接続情報を設定します。

```vim
let g:simplynote_api_url = 'http://localhost:8000'
let g:simplynote_username = 'your-name'
let g:simplynote_password = 'your-password'

" 任意: デバッグログを表示
let g:simplynote_debug = 0
```

`g:simplynote_api_url` の既定値は `http://localhost:8000` です。ユーザー名とパスワードを設定しておくと、初回アクセス時やトークン期限切れ時に自動ログインします。

> [!CAUTION]
> `vimrc` にパスワードを記載する場合は、設定ファイルの共有範囲やアクセス権に注意してください。

手動ログインには `:SNLogin username password` を使用します。

## 基本的な使い方

1. `:SimplyNoteList` でノート一覧を開きます。
2. 一覧でカーソルを動かすと、選択中のノートが下の本文ビューに表示されます。
3. `e` で本文ビューへ移動し、編集モードに入ります。
4. 編集後に `:w` でサーバーへ保存します。
5. 一覧へ戻るには通常のウィンドウ移動（例: `<C-w>k`）を使います。
6. `q` で一覧と本文ビューを閉じます。

編集時は、1行目がタイトル、2行目以降が本文として保存されます。

### 一覧バッファのキー操作

| キー | 動作 |
| --- | --- |
| `u` | ノート一覧を更新 |
| `e` | 選択中のノートを編集 |
| `J` | フォーカスを移さず本文を1行下へスクロール |
| `K` | フォーカスを移さず本文を1行上へスクロール |
| `5J` / `5K` | 指定した行数だけ本文をスクロール |
| `q` | 一覧と本文ビューを閉じる |

### 本文ビューのキー操作

| キー | 動作 |
| --- | --- |
| `:w` | ノートを保存 |
| `gx` | カーソル位置のURLをブラウザで開く |
| `<C-LeftMouse>` | クリックしたURLをブラウザで開く |

## コマンド

| コマンド | 説明 |
| --- | --- |
| `:SimplyNoteList` | ノート一覧を開く |
| `:SimplyNoteUpdate` | ノート一覧を更新する |
| `:SimplyNoteOpen` | 一覧で選択中のノートを開く |
| `:SimplyNoteEdit` | 本文ビューを編集可能にする |
| `:SimplyNoteSave` | ノートをサーバーへ保存する |
| `:SimplyNoteNew` | 新しいノートを作成する |
| `:SimplyNoteDelete` | 開いているノートを削除する |
| `:SNLogin [username] [password]` | SimplyNoteへログインする |

## 表示と編集に関する注意

- 一覧にはタイトル、タグ、スター、添付ファイル数、更新日時を表示します。
- 添付ファイルは本文末尾にリンクとして表示されます。現在、Vim側からのアップロードや削除には対応していません。
- 本文ビューに未保存の変更がある間は、別のノートを選んでも自動プレビューを切り替えません。保存するか、変更を破棄してから選択し直してください。
- `trash` タグ付きノートは一覧に表示しません。

## ヘルプ

詳細は `:help simplynote` で確認できます。
