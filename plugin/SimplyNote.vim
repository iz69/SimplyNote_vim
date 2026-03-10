" plugin/simplynote.vim
if exists('g:loaded_simplynote')
  finish
endif

let g:loaded_simplynote = 1

command! -nargs=0 SimplyNoteList   call SimplyNote#list()
command! -nargs=0 SimplyNoteOpen   call SimplyNote#open()
command! -nargs=0 SimplyNoteUpdate call SimplyNote#update()
command! -nargs=0 SimplyNoteSave   call SimplyNote#save()
command! -nargs=0 SimplyNoteEdit   call SimplyNote#edit()
command! -nargs=0 SimplyNoteNew    call SimplyNote#new()
command! -nargs=0 SimplyNoteDelete call SimplyNote#delete()
command! -nargs=* SNLogin          call SimplyNote#login(<f-args>)

" need python37
