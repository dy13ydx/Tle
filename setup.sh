#!/usr/bin/env bash
# Download dotfiles
curl -sO https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/.tmux.conf
curl -sO https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/.inputrc
curl -sO https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/.vimrc

# Prepare directories
mkdir -p ~/.config/bin
mkdir -p ~/.local/bin

# Download custom scripts and tools
curl -s https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/target -o ~/.local/bin/target
curl -s https://raw.githubusercontent.com/dy13ydx/Tle/refs/heads/master/yxp -o ~/.local/bin/yxp
chmod +x ~/.local/bin/target ~/.local/bin/yxp

# Install clipboard tools
sudo apt install -y xclip xsel

# Create folder for payloads
mkdir -p dy13ydx && cd dy13ydx

# Download nc.exe
curl -sOJ https://raw.githubusercontent.com/int0x33/nc.exe/master/nc64.exe

# Download Vimium settings
curl -sO https://raw.githubusercontent.com/heads/master/vimium.json

# Open Firefox extension page
firefox https://addons.mozilla.org/en-GB/firefox/addon/vimium-ff/

echo "[✓] Setup complete. Launching interactive Bash..."
exec bash --login -i
