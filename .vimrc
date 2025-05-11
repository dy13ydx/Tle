set nu rnu
set mouse=a
set autoindent
set softtabstop=4
set shiftwidth=2
set tabstop=4
syntax on
set ruler
"Shift + Tab does inverse tab
inoremap <S-Tab> <C-d>
"See invisible characters
set list listchars=tab:>\ ,trail:+,eol:$
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
let &t_te .= "\e[2 q"  " cursor when vim exits
