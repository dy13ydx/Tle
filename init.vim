" --- Core System & Engine ---
syntax on
filetype plugin indent on
set background=dark
set notermguicolors
colorscheme vim

" --- Visuals & UI ---
set nu rnu
set ruler
set hlsearch
set mouse=a
set cmdheight=0

" --- Default Indentation ---
set autoindent
set noexpandtab
set tabstop=4
set softtabstop=4
set shiftwidth=2

" --- Language Specific: Python Override ---
autocmd FileType python setlocal expandtab shiftwidth=4 tabstop=4 softtabstop=4

" --- Invisible Characters ---
set list listchars=tab:^I,trail:+,eol:$
highlight NonText ctermfg=green guifg=red
highlight SpecialKey ctermfg=green guifg=red
highlight EndOfBuffer ctermfg=green guifg=red

" --- Key Bindings & Behavior ---
inoremap <S-Tab> <C-d>
set whichwrap+=<,>,[,]

" --- Cursor Shapes ---
set guicursor=n-v-c:block,i-ci-ve:ver25,r-cr:hor20
