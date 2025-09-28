#!/usr/bin/env bash
set -e    # stop if anything fails

# 1. Set MATE window-switch shortcut
gsettings set org.mate.Marco.global-keybindings switch-windows '<Alt>grave'

# 2. Download dotfiles
curl -fsSLo ~/.tmux.conf https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/.tmux.conf
curl -fsSLo ~/.inputrc    https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/.inputrc
curl -fsSLo ~/.vimrc      https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/.vimrc

# NOTE: bash loads ~/.inputrc automatically for interactive shells;
#       bind -f is not needed here.

# 3. Prepare directories
mkdir -p ~/.config/bin
mkdir -p ~/.local/bin

# 4. Download helper scripts
curl -fsSL https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/target -o ~/.local/bin/target
curl -fsSL https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/yxp    -o ~/.local/bin/yxp
chmod +x ~/.local/bin/target ~/.local/bin/yxp

# 5. Install clipboard tools
sudo apt update -y
sudo apt install -y xclip xsel

# 6. Grab nc.exe and Vimium config
mkdir -p ~/dy13ydx && cd ~/dy13ydx
curl -fsSLO https://raw.githubusercontent.com/int0x33/nc.exe/master/nc64.exe
curl -fsSLO https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/vimium.json

# 7. Open Vimium extension page in Firefox
firefox https://addons.mozilla.org/en-GB/firefox/addon/vimium-ff/

echo "[✓] Bootstrap finished — dropping into interactive Bash and starting tmux…"

# 8. Switch to a fresh interactive Bash so .inputrc loads, then auto-start tmux
exec bash --login -i -c tmux
