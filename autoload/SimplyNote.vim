" autoload/SimplyNote.vim
" ======================================

" デバッグ出力関数
function! SimplyNote#log(msg) abort
  if get(g:, 'simplynote_debug', 0)
    echom '[SimplyNote] ' . string(a:msg)
  endif
endfunction

" ------------------------------------------------------------------

" HTTP通信（Python連携）
function! SimplyNote#request(path, opts) abort

  let base_url = substitute(get(g:, 'simplynote_api_url', 'http://localhost:8000'), '/$', '', '')
  let url     = base_url . a:path
  let method  = get(a:opts, 'method', 'GET')
  let headers = get(a:opts, 'headers', {})
  let body    = get(a:opts, 'body', '')

  call SimplyNote#log('HTTP begin')
  call SimplyNote#log('HTTP url=' . url)
  call SimplyNote#log('HTTP method=' . method)
  call SimplyNote#log('HTTP headers=' . string(headers))
  call SimplyNote#log('HTTP body_len=' . len(body))
 
  let g:_simplynote_req = {
        \ 'url': url,
        \ 'method': method,
        \ 'headers': headers,
        \ 'body': body,
        \ }

  " ------------
  py3 << EOF
import json, ssl, traceback
from urllib import request, error

r = vim.vars['_simplynote_req']
out = {}

def _to_str(x):
    return x.decode('utf-8') if isinstance(x, (bytes, bytearray)) else str(x)

try:
    url = _to_str(r['url'])
    method = _to_str(r['method'])
    headers = { _to_str(k): _to_str(v) for k, v in r['headers'].items() }
    # JSONでないリクエストも考慮し、Content-Typeのデフォルト設定は行わない（呼び出し元に任せる）
    data = r['body']
    if isinstance(data, str):
        data = data.encode('utf-8')

    ctx = ssl.create_default_context()
    req_obj = request.Request(url, data=data, headers=headers, method=method)
    try:
        res = request.urlopen(req_obj, context=ctx, timeout=10)
        txt = res.read().decode('utf-8', 'ignore')
        status = res.getcode()
        try:
            # JSONとしてパース成功
            j = json.loads(txt)
            vim.vars['_simplynote_result'] = j
        except Exception:
            # JSONパース失敗（テキストとして返す）
            out['text'] = txt
            out['status'] = status
            out['resp_headers'] = dict(res.headers.items())
            vim.vars['_simplynote_result'] = out
    except error.HTTPError as e:
        body = e.read().decode('utf-8', 'ignore')
        status = e.code
        headers = dict(e.headers.items())
        try:
            # エラーボディをJSONとしてパース成功
            j = json.loads(body)
            j['status'] = status
            j['resp_headers'] = headers
            vim.vars['_simplynote_result'] = j
        except Exception:
            # エラーボディのJSONパース失敗
            out['error'] = 'HTTPError'
            out['status'] = status
            out['text'] = body
            out['resp_headers'] = headers
            vim.vars['_simplynote_result'] = out

except Exception as e:
    out['error'] = str(e)
    out['trace'] = traceback.format_exc()
    vim.vars['_simplynote_result'] = out

EOF
  " ------------

  let result = get(g:, '_simplynote_result', {})
  call SimplyNote#log('HTTP RESULT raw=' . string(result))
  return result
endfunction

" ------------------------------------------------------------------

" トークンの存在を確認し、必要に応じて自動ログインを試みるヘルパー関数
" 成功時: 1, 失敗時: 0 を返す
function! s:ensure_auth() abort
  if exists('g:simplynote_token') && !empty(g:simplynote_token)
    return 1
  endif

  let user = get(g:, 'simplynote_username', '')
  let pass = get(g:, 'simplynote_password', '')

  if user ==# '' || pass ==# ''
    return 0
  endif

  call SimplyNote#login(user, pass)

  if exists('g:simplynote_token') && !empty(g:simplynote_token)
    return 1
  else
    return 0
  endif
endfunction

" ------------------------------------------------------------------

" ログイン処理
function! SimplyNote#login(...) abort

  if a:0 >= 2
    let username = a:1
    let password = a:2
  else
    let username = get(g:, 'simplynote_username', '')
    let password = get(g:, 'simplynote_password', '')
  endif
  
  if username == '' || password == ''
    echohl ErrorMsg | echo "Username or password not set. Use :SNLogin user pass or set g:simplynote_username/password" | echohl None
    return
  endif
  
  let body = 'username=' . username . '&password=' . password
  let opts = {
  \ 'method': 'POST',
  \ 'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
  \ 'body': body
  \}
  
  let res = SimplyNote#request('/auth/token', opts)
  
  if has_key(res, 'access_token')
    let g:simplynote_token = res['access_token']
    if a:0 < 2 " :SNLogin コマンドなどで明示的に実行された場合のみメッセージ表示
      echo "✅ Login successful"
    endif
  else
    if a:0 < 2
      echohl ErrorMsg | echo "Login failed" | echohl None
      if has_key(res, 'error')
        echom 'Error detail: ' . res['error']
      endif
    endif
  endif
endfunction

" ------------------------------------------------------------------

" ノート一覧を更新・再描画
function! SimplyNote#update() abort

  " --- トークン確認＆自動ログイン ---
  if !<SID>ensure_auth()
    echohl ErrorMsg | echo "ログイン情報が未設定、または自動ログインに失敗しました。" | echohl None
    return
  endif
  
  " --- APIからノート一覧を取得 ---
  let opts = {
  \ 'method': 'GET',
  \ 'headers': {'Authorization': 'Bearer ' . g:simplynote_token}
  \}
  let res = SimplyNote#request('/notes', opts)
  
  " --- 401 (トークン切れ) リトライロジックを共通関数に移行 ---
  if type(res) == type({}) && get(res, 'status', 0) == 401
    call SimplyNote#log('Received 401. Retrying auth and request.')
    if <SID>ensure_auth() " 再ログイン試行
      " ヘッダーを更新してリトライ
      let opts.headers = {'Authorization': 'Bearer ' . g:simplynote_token}
      let res = SimplyNote#request('/notes', opts)
    else
      echohl ErrorMsg | echo "トークンが失効しました。再ログインに失敗。" | echohl None
      return
    endif
  endif
  " -----------------------------------------------------

  let notes = type(res) == type([]) ? res : (has_key(res, 'notes') ? res.notes : [])

  if empty(notes)
    echohl ErrorMsg | echo "ノート一覧の取得に失敗しました。" | echohl None
    return
  endif

  " ---- Trash タグを持つノートを除外 ----
  if type(notes) == v:t_list
    let notes = filter(copy(notes), {_, n ->
          \ index(map(copy(get(n, 'tags', [])), {_, t -> tolower(t)}), 'trash') == -1
          \ })
  endif
  
  " --- 一覧行を組み立て ---
  let lines = []

  for note in notes

"    let title = get(note, 'title', '[No Title]')
    let title = empty(get(note, 'title', '')) ? '[No Title]' : get(note, 'title', '')

    let tags = get(note, 'tags', [])
    let tag_str = len(tags) > 0 ? '[#' . join(tags, '|#') . ']' : ''

"    let has_files = has_key(note, 'files') && type(note.files) == v:t_list && len(note.files) > 0
"    let file_mark = has_files ? ' [+]' : ''

    let file_count = (has_key(note, 'files') && type(note.files) == v:t_list)
        \ ? len(note.files)
        \ : 0
    let file_mark = file_count > 0 ? '[+'.file_count.']' : ''

    " --- 重要フラグ（[*]）---
"    let star_mark = (get(note, 'is_important', 0) == 1) ? '[*]' : ''
    let isimp = str2nr(get(note, 'is_important', 0))
    let star_mark = (isimp == 1) ? '[*]' : ''

    let datetime_str = get(note, 'updated_at', get(note, 'created_at', ''))

    if datetime_str !=# ''
      let local = <SID>ToLocalTime(datetime_str)
      let datetime = '[' . local . ']'
    else
      let datetime = '[????-??-?? ??:??]'
    endif

    " 左詰め Star タイトル タグ
    let left = ''
    if star_mark !=# ''
      let left .= star_mark
    endif
    let left .= title
    if tag_str !=# ''
      let left .= ' ' . tag_str
    endif

    " 右詰め 添付 日付
    let right = ''
    if file_mark !=# ''
      let right .= file_mark
    endif
"    if star_mark !=# ''
"      let right .= star_mark
"    endif
    let right .= datetime

    let termwidth = &columns - 2
    let spaces = max([1, termwidth - strdisplaywidth(left) - strdisplaywidth(right)])
    call add(lines, left . repeat(' ', spaces) . right)
  endfor
  
  " --- 現在バッファに反映 ---
  setlocal modifiable
  call setline(1, lines)
  let b:simplynote_notes = notes
  setlocal nomodifiable cursorline nowrap
  normal! gg
  
  let v:statusmsg = "🔄 Updated Note List"
  
  " --- バッファを保存済み扱いに ---
  setlocal nomodified

endfunction


function! s:ToLocalTime(utc_str) abort
  if empty(a:utc_str)
    return ''
  endif

  " Python 表現として安全に変換（クォートエスケープ含む）
  let py_utc = string(a:utc_str)

  " Python 式を 1 行の文字列で作成
  let py = "__import__('datetime').datetime.fromisoformat(" ..
        \ py_utc ..
        \ ".replace('Z', '+00:00')).astimezone().strftime('%Y-%m-%d %H:%M:%S')"

  return py3eval(py)
endfunction

" ------------------------------------------------------------------

" ノート一覧ペインを開く（必要に応じて新規作成）
function! SimplyNote#list() abort

  let list_buf = bufnr('[SimplyNoteList]')
  let view_buf = bufnr('[SimplyNoteView]')

  " --- 一覧バッファを準備 ---
  if list_buf == -1
    silent! noautocmd keepalt tabnew
    silent! noautocmd setlocal buftype=nofile bufhidden=hide noswapfile nowrap nonumber norelativenumber
    silent! noautocmd file [SimplyNoteList]
  else
    execute 'tabnext | buffer ' . list_buf
  endif

  " --- ノート一覧を更新 ---
  call SimplyNote#update()

  " --- 表示設定 ---
  silent! syntax clear SimplyNoteTag
"  silent! syntax clear SimplyNoteFileMark
  silent! syntax clear SimplyNoteFileCount
  silent! syntax clear SimplyNoteImportant
  silent! syntax clear SimplyNoteDatetime

  syntax match SimplyNoteTag /\v\[#([^\]]+)\]/
  highlight def link SimplyNoteTag Type

"  syntax match SimplyNoteFileMark /\v\[\*\]/
"  highlight def link SimplyNoteFileMark Constant

"  syntax match SimplyNoteFileCount /\v\[\+\d+\]/
  syntax match SimplyNoteFileCount /\[\+\d\+\]/
  highlight def link SimplyNoteFileCount Constant

"  syntax match SimplyNoteImportant /\v\[\*\]/
  syntax match SimplyNoteImportant /\[\*\]/
  highlight def link SimplyNoteImportant Special

  syntax match SimplyNoteDatetime /\v\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}\]/
  highlight def link SimplyNoteDatetime Comment

  " --- 下ペイン（本文） ---
  if view_buf == -1
    silent! noautocmd belowright split
    silent! noautocmd enew
    silent! noautocmd setlocal buftype= bufhidden=hide noswapfile norelativenumber
    silent! noautocmd file [SimplyNoteView]
    silent! call setline(1, [' (Please select a note from the list.)'])
    silent! wincmd k
  else
    execute 'belowright split | buffer ' . view_buf
    silent! wincmd k
  endif

  " カーソル移動時はプレビューだけ（読み取り専用）
  augroup SimplyNoteAutoPreview
    autocmd!
    autocmd CursorMoved <buffer> call SimplyNote#open()
  augroup END
 
  " u: SimplyNoteUpdate
  nnoremap <buffer> u :silent call SimplyNote#update()<CR>

  " e: Viewへ移動してSimplyNoteEdit実行
  nnoremap <buffer> e :silent call <SID>GotoView()<Bar>SimplyNoteEdit<CR>

  " q: 一覧とビューを閉じる
  nnoremap <buffer> q :silent call <SID>CloseAll()<CR>

endfunction

" -------

function! s:CloseAll() abort
  " ビューバッファを閉じる
  let view_buf = bufnr('[SimplyNoteView]')
  if view_buf != -1
    execute 'bwipeout! ' . view_buf
  endif

  " リストバッファ自身を閉じる
  let list_buf = bufnr('[SimplyNoteList]')
  if list_buf != -1
    execute 'bwipeout! ' . list_buf
  endif
endfunction

" -------

function! s:GotoView() abort
  let view_buf = bufnr('[SimplyNoteView]')
  let view_win = (view_buf == -1) ? -1 : bufwinnr(view_buf)

  if view_win != -1
    " Viewウィンドウにカーソルを移動
    execute view_win . 'wincmd w'
  else
    " Viewウィンドウがない場合は、SimplyNote#open()でViewバッファを開く
    call SimplyNote#open()
    " open() の中でリストへ戻る処理も入っているため、再度Viewへ移動する処理を追加
    let view_win = (bufnr('[SimplyNoteView]') == -1) ? -1 : bufwinnr(bufnr('[SimplyNoteView]'))
    if view_win != -1
      execute view_win . 'wincmd w'
    endif
  endif
endfunction

" ------------------------------------------------------------------

function! SimplyNote#open() abort

  " リスト側の保管データ確認
  if !exists('b:simplynote_notes')
    return
  endif
  let lnum = line('.')
  if lnum < 1 || lnum > len(b:simplynote_notes)
    return
  endif
  let note = b:simplynote_notes[lnum - 1]

  " ---- View バッファ/ウィンドウの存在確認 ----
  let view_buf = bufnr('[SimplyNoteView]')
  let view_win = (view_buf == -1) ? -1 : bufwinnr(view_buf)

  if view_win == -1
    " ウィンドウが無い → 分割して表示する
    belowright split
    if view_buf == -1
      " バッファ自体も無い → 新規作成
      enew

      file [SimplyNoteView]
      setlocal buftype= bufhidden=hide noswapfile norelativenumber
    else
      execute 'buffer ' . view_buf
    endif
  else
    execute view_win . 'wincmd w'
  endif

  " ---- 内容描画 ----
  setlocal modifiable
  silent! %delete _

  " viewerバッファにノート情報を保持
  let b:simplynote_id = note.id
  let b:simplynote_title = note.title
  let b:simplynote_tags = get(note, 'tags', [])
  let b:simplynote_files = get(note, 'files', [])
  
  let title = get(note, 'title', '[No Title]')

  " 改行コード(念の為)
  let raw = get(note, 'content', '')
  let cleaned = substitute(raw, '\r', '', 'g')
  let content = split(cleaned, '\n')

  call setline(1, [title, repeat('─', strdisplaywidth(title))] + content)

  " --- 添付ファイルを表示 ---
  if has_key(note, 'files') && type(note.files) == v:t_list && len(note.files) > 0
    " 添付部分の開始行を記録
    let attach_start = line('$') + 1
    call append('$', '')
    call append('$', '--- Attached files ---')
    let base = substitute(get(g:, 'simplynote_api_url', 'http://localhost:8000'), '/$', '', '')
    for f in note.files
      let url = f.url
      if url =~# '^/'
        let url = base . url
      endif
      call append('$', printf('- [%s](%s)', f.filename, url))
    endfor

  endif

  " ---- :w 時のサーバ保存フック ----
  augroup SimplyNoteWriteHook
    autocmd! * <buffer>
    autocmd BufWriteCmd <buffer> call SimplyNote#save()
  augroup END

  " ここで「保存済み」フラグを明示的に立てる
  setlocal nomodified

  " Viewバッファを読み取り専用にする
  setlocal nomodifiable readonly

  " ---- 色付け & URLクリック設定 ----
  silent! syntax clear SimplyNoteAttachTitle
  silent! syntax clear SimplyNoteAttachLink

  syntax match SimplyNoteAttachTitle /^--- Attached files ---$/
  syntax match SimplyNoteAttachLink /https\?:\/\/[^ )]\+/ containedin=ALL

  highlight def link SimplyNoteAttachTitle Identifier
  highlight def link SimplyNoteAttachLink Underlined

  " gx と Ctrl+クリックでURLを開けるように
  if has('win32') || has('win64')
    nnoremap <buffer> gx :execute '!start "" ' . shellescape(expand('<cWORD>'))<CR>
    nnoremap <buffer> <C-LeftMouse> :execute '!start "" ' . shellescape(expand('<cWORD>'))<CR>
  else
    nnoremap <buffer> gx :execute '!xdg-open ' . shellescape(expand('<cWORD>'))<CR>
    nnoremap <buffer> <C-LeftMouse> :execute '!xdg-open ' . shellescape(expand('<cWORD>'))<CR>
  endif

  normal! gg

  " リストへ戻る（存在すれば）
  let list_buf = bufnr('[SimplyNoteList]')
  let list_win = (list_buf == -1) ? -1 : bufwinnr(list_buf)
  if list_win != -1
    execute list_win . 'wincmd w'
  endif

endfunction

" ------------------------------------------------------------------

function! SimplyNote#edit() abort

  if &modifiable
    echo "Already editable."
    return
  endif

  " 添付ファイルセクションを削除し、バックアップする
  let l:lines = getline(1, '$')
  let l:attach_idx = -1
  
  for i in range(len(l:lines))
    if l:lines[i] =~# '^--- Attached files ---'
      let l:attach_idx = i + 1
      break
    endif
  endfor

  if l:attach_idx >= 1
    " 添付ファイルセクションをバッファローカル変数にバックアップ
    let b:simplynote_attached_lines = l:lines[l:attach_idx - 1:]
    " バッファから添付ファイルセクションを削除
    setlocal modifiable " 削除のために modifiable に設定
    silent! execute l:attach_idx . ',$delete _'
    setlocal nomodifiable " 一旦 nomodifiable に戻す
  else
    " 添付ファイルがなければバックアップ変数を消しておく
    unlet! b:simplynote_attached_lines
  endif

  " タイトル下の罫線を自動除去
  let l2 = getline(2)
  if l2 =~# '^\%u2500\+$'
    silent! 2delete _
  endif

  setlocal modifiable noreadonly
  echo "✏️  Edit mode enabled.  Use :SimplyNoteSave to update."

endfunction

" ------------------------------------------------------------------

function! SimplyNote#save() abort

  " --- トークン確認＆自動ログイン ---
  if !<SID>ensure_auth()
    echohl ErrorMsg | echo "Login information is not configured, or automatic login has failed." | echohl None
    return
  endif

  " --- ノート内容を取得 ---
  " (中略: 内容取得ロジックは変更なし)
  let lines = getline(1, '$')
  if empty(lines)
    echohl WarningMsg | echo "An empty note cannot be saved." | echohl None
    return
  endif
  
  " --- 添付ファイルセクションを除外 ---
  let attach_idx = -1
  for i in range(len(lines))
    if lines[i] =~# '^--- Attached files ---'
      let attach_idx = i
      break
    endif
  endfor
  if attach_idx >= 0
    let lines = lines[:attach_idx - 1]
  endif
  
  " 1行目をタイトル、2行目以降を本文として分割
  let l:title = trim(get(lines, 0, ''))
  if empty(l:title)
    let l:title = 'New Note'
  endif
  
  " 1行目をタイトル、2行目が罫線ならスキップ
  let l:title = trim(get(lines, 0, ''))
  let l:content_lines = []
  if len(lines) >= 2 && get(lines, 1, '') =~# '^\%u2500\+$'
    let l:content_lines = lines[2:]
  else
    let l:content_lines = lines[1:]
  endif
  let l:content = join(l:content_lines, "\n")
  
  " --- HTTPヘッダ ---
  let l:headers = {'Authorization': 'Bearer ' . g:simplynote_token, 'Content-Type': 'application/json; charset=utf-8'}
  
  " --- APIパスとメソッドを決定 ---
  if exists('b:simplynote_id')
    let l:path = '/notes/' . b:simplynote_id
    let l:method = 'PUT'
  else
    let l:path = '/notes'
    let l:method = 'POST'
  endif
  
  " --- JSON本文を作成 ---
  let l:body = json_encode({'title': l:title, 'content': l:content})

  " --- HTTP送信 ---
  let opts = {
  \ 'method': l:method,
  \ 'headers': l:headers,
  \ 'body': l:body
  \}
  
  call SimplyNote#log('Save: ' . l:method . ' ' . l:path)
  let l:res = SimplyNote#request(l:path, opts)
  
  " --- 401 (トークン切れ) リトライロジックを共通関数に移行 ---
  if type(l:res) == type({}) && get(l:res, 'status', 0) == 401
    call SimplyNote#log('Received 401 on save. Retrying auth and request.')
    if <SID>ensure_auth() " 再ログイン試行
      " ヘッダーを更新してリトライ
      let opts.headers = {'Authorization': 'Bearer ' . g:simplynote_token, 'Content-Type': 'application/json; charset=utf-8'}
      let l:res = SimplyNote#request(l:path, opts)
    else
      echohl ErrorMsg | echo "Your token has expired. Automatic re-login failed." | echohl None
      return
    endif
  endif

  " --- 結果処理 ---
  if has_key(l:res, 'id')

    let b:simplynote_id = l:res.id
    let b:simplynote_title = l:res.title
    if l:method ==# 'POST'
      echo "🆕 Create a new note: " . l:res.title
    else
      echo "💾 Updated the note: " . l:res.title
    endif

    " View バッファの保護を一時的に解除
    setlocal modifiable noreadonly

    " 修正開始: 保存成功時に添付ファイルセクションを復元
    if exists('b:simplynote_attached_lines')
      setlocal modifiable " 追記のために modifiable に設定
      call append('$', b:simplynote_attached_lines)
      unlet b:simplynote_attached_lines " バックアップを消去
    endif

    " 編集モードを終了する (読み取り専用に戻る)
    setlocal nomodifiable readonly

    " 変更フラグをリセット (保存成功時)
    setlocal nomodified

    " 一覧更新
    call SimplyNote#refresh(b:simplynote_id)

  elseif has_key(l:res, 'error')
    echohl ErrorMsg | echo "Note save error: " . l:res.error | echohl None
  else
    echohl ErrorMsg | echo "Failed to save the note." | echohl None
  endif
 
endfunction

" ------------------------------------------------------------------

function! SimplyNote#refresh(note_id) abort
  let list_buf = bufnr('[SimplyNoteList]')
  if list_buf == -1
    return
  endif
  " リストウィンドウへ移動
  let list_win = bufwinnr(list_buf)
  if list_win != -1
    execute list_win . 'wincmd w'
    call SimplyNote#update()
    " id一致の行を探す
    if exists('b:simplynote_notes')
      let idx = -1
      for i in range(len(b:simplynote_notes))
        if get(b:simplynote_notes[i], 'id', '') ==# a:note_id
          let idx = i
          break
        endif
      endfor
      if idx >= 0
        execute (idx+1)
      endif
    endif
  endif
endfunction

" ------------------------------------------------------------------

" 新規ノート
function! SimplyNote#new() abort
  let view_buf = bufnr('[SimplyNoteView]')
  if view_buf == -1
    belowright split | enew | file [SimplyNoteView]
  else
    execute 'belowright split | buffer ' . view_buf
  endif

  " 一時ファイルを割り当て（新規は tempname() でOK）
"  let tmpfile = tempname()
"  execute 'file ' . fnameescape(tmpfile)

  " 通常バッファ化
"  setlocal modifiable buftype=nofile bufhidden=hide swapfile norelativenumber
  setlocal modifiable buftype= bufhidden=hide swapfile norelativenumber
  silent! %delete _
  call setline(1, ['New Note', ''])

  " 新規なのでメタ情報は消す
  unlet! b:simplynote_id b:simplynote_title b:simplynote_tags b:simplynote_files

  " ここで保存済み扱いにしてから編集を促す（任意）
  setlocal nomodified
  echo "📝 Creating a new note. Use :w save it."

  " :w 後のサーバ保存フック
  augroup SimplyNoteWriteHook
    autocmd! * <buffer>
    autocmd BufWriteCmd <buffer> call SimplyNote#save()
  augroup END

endfunction


" ------------------------------------------------------------------

" 削除（確認→DELETE→一覧更新）
function! SimplyNote#delete() abort
  if !exists('b:simplynote_id')
    echohl WarningMsg | echo "This note has no ID.(it may not have been saved)" | echohl None
    return
  endif
  if confirm('Are you sure you want to delete it', "&Yes\n&No", 2) != 1
    return
  endif
  
  " --- トークン確認＆自動ログイン ---
  if !<SID>ensure_auth()
    echohl ErrorMsg | echo "You are not logged in, or automatic login has failed." | echohl None
    return
  endif
  
  let opts = {'method': 'DELETE', 'headers': {'Authorization': 'Bearer ' . g:simplynote_token}}
  let res = SimplyNote#request('/notes/' . b:simplynote_id, opts)
  
  " --- 401 (トークン切れ) リトライロジックを共通関数に移行 ---
  if type(res) == type({}) && get(res, 'status', 0) == 401
    call SimplyNote#log('Received 401 on delete. Retrying auth and request.')
    if <SID>ensure_auth() " 再ログイン試行
      " ヘッダーを更新してリトライ
      let opts.headers = {'Authorization': 'Bearer ' . g:simplynote_token}
      let res = SimplyNote#request('/notes/' . b:simplynote_id, opts)
    else
      echohl ErrorMsg | echo "Your token has expired. Automatic re-login failed." | echohl None
      return
    endif
  endif

  echo "🗑️ The note has been deleted."
  " ビューをクリアして一覧更新
  silent! %delete _
  call setline(1, [' (Please select a note from the list.)'])
  call SimplyNote#refresh('')
  
  if type(res)==type({}) && (get(res,'error','') != '' || get(res,'status',200) >= 400)
    echohl ErrorMsg | echo "Failed to delete the note." | echohl None
  endif
endfunction

