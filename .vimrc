"Show absolute line number on the current line, relative on others
set nu rnu
"Enable mouse support (click, scroll, select)
set mouse=a
"Copy indentation from the previous line when starting a new one
set autoindent
"Number of spaces a <Tab> counts for in insert mode (soft tabs)
set softtabstop=4
"Number of spaces used for each step of (auto)indent
set shiftwidth=2
"Display width of a real tab character (\t)
set tabstop=4
"Highlight all matches when searching
set hlsearch
"Enable syntax highlighting (colors for code/text)
syntax on
"Show cursor position (line, column, % of file) in the status line
set ruler
"Shift + Tab does inverse tab
inoremap <S-Tab> <C-d>
"See invisible characters
set list listchars=tab:^I,trail:+,eol:$
"wrap to next line when end of line is reached
set whichwrap+=<,>,[,]
"Hihglight invisible characters
highlight NonText ctermfg=green guifg=red
highlight Specialkey ctermfg=green guifg=red
"Change cursor  chape base on mode
"Ps = 0  -> blinking block
"Ps = 1  -> blinking block (default)
"Ps = 2  -> steady block
"Ps = 3  -> blinking underline
"Ps = 4  -> steady underline
"Ps = 5  -> blinking bar (xterm)
"Ps = 6  -> steady bar (xterm)
let &t_SI = "\e[5 q"   " cursor in insert mode
let &t_EI = "\e[2 q"   " cursor in normal mode
let &t_SR = "\e[3 q"   " cursor in replace mode
let &t_ti .= "\e[2 q"  " cursor when vim starts
let &t_te .= "\e[5 q"  " cursor when vim exits
"Fixes glitch? in colors when using vim with tmux
set background=dark
set t_Co=256
