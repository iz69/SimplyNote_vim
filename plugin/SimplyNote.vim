" plugin/simplynote.vim
if exists('g:loaded_simplynote')
  finish
endif

let g:loaded_simplynote = 1

" command! -nargs=* SimplyNoteLogin  call SimplyNote#login(<f-args>)
command! -nargs=0 SimplyNoteList   call SimplyNote#list()
command! -nargs=0 SimplyNoteUpdate call SimplyNote#update()
command! -nargs=0 SimplyNoteSave   call SimplyNote#save()
command! -nargs=0 SimplyNoteEdit   call SimplyNote#edit()

" need python37 
