" --- Core System & Engine ---
syntax on                   " Enable syntax highlighting
filetype plugin indent on   " Native filetype detection
set background=dark         " Fixes color glitch when using vim with tmux
set t_Co=256                " Enable 256 colors

" --- Visuals & UI ---
set nu rnu                  " Hybrid line numbers
set ruler                   " Show cursor position
set hlsearch                " Highlight all matching words when searching
set mouse=a                 " Enable mouse clicks/scrolling

" --- Default Indentation ---
set autoindent              " Copy the indentation of the previous line
set noexpandtab             " Keep real tabs (\t) instead of spaces by default
set tabstop=4               " A real tab character looks 4 spaces wide
set softtabstop=4           " Tab key inserts a 4-space wide tab
set shiftwidth=2            " Use 2 spaces for auto-indenting (e.g., using >>)

" --- Language Specific: Python Override ---
" Force 4 spaces instead of tabs to prevent IndentationErrors
autocmd FileType python setlocal expandtab shiftwidth=4 tabstop=4 softtabstop=4

" --- Invisible Characters ---
" See invisible characters (Tabs as ^I, trailing spaces as +, end of line as $)
set list listchars=tab:^I,trail:+,eol:$
" Highlight invisible characters with specific colors
highlight NonText ctermfg=green guifg=red
highlight Specialkey ctermfg=green guifg=red

" --- Key Bindings & Behavior ---
" Shift + Tab does inverse tab
inoremap <S-Tab> <C-d>
" Wrap to next line when end of line is reached
set whichwrap+=<,>,[,]

" --- Cursor Shapes (Based on Mode) ---
" Ps = 0/1 -> blinking block (default), Ps = 2 -> steady block
" Ps = 3   -> blinking underline, Ps = 4 -> steady underline
" Ps = 5   -> blinking bar (xterm), Ps = 6 -> steady bar (xterm)
let &t_SI = "\e[5 q"   " cursor in insert mode
let &t_EI = "\e[2 q"   " cursor in normal mode
let &t_SR = "\e[3 q"   " cursor in replace mode
let &t_ti .= "\e[2 q"  " cursor when vim starts
let &t_te .= "\e[5 q"  " cursor when vim exits
