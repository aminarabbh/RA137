#!/bin/bash

set -e


BIN_DIR="/usr/sbin"

TMP_DIR="/tmp/ra137_install"

mkdir -p $TMP_DIR

cd $TMP_DIR


echo "[+] Installing dependencies"

apt update -y

apt install -y --fix-broken \
    wget \
    curl \
    unzip \
    git \
    python3 \
    python3-pip \
    jq \
    nmap \
    fonts-dejavu-core \
    || echo "[!] Some apt packages failed – continuing anyway"


download_binary() {

    NAME=$1
    URL=$2
    ARCHIVE=$3
    BINARY=$4
    RENAME_AS=${5:-$BINARY}

    if command -v $RENAME_AS &>/dev/null || [ -f "$BIN_DIR/$RENAME_AS" ]; then
        echo "[=] $RENAME_AS already installed – skipping"
        return 0
    fi

    echo "[+] Installing $NAME"

    wget -q -O $ARCHIVE $URL

    unzip -o $ARCHIVE

    chmod +x $BINARY

    mv $BINARY $BIN_DIR/$RENAME_AS

}


echo "[+] Installing subfinder"

download_binary \
"subfinder" \
"https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_linux_amd64.zip" \
"subfinder.zip" \
"subfinder"


echo "[+] Installing httpx"

download_binary \
"httpxx" \
"https://github.com/projectdiscovery/httpx/releases/download/v1.9.0/httpx_1.9.0_linux_amd64.zip" \
"httpx.zip" \
"httpx" \
"httpxx"
echo "......"


echo "[+] Installing dnsx"

download_binary \
"dnsx" \
"https://github.com/projectdiscovery/dnsx/releases/download/v1.2.3/dnsx_1.2.3_linux_amd64.zip" \
"dnsx.zip" \
"dnsx"


echo "[+] Installing nuclei"

download_binary \
"nuclei" \
"https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_amd64.zip" \
"nuclei.zip" \
"nuclei"


echo "[+] Installing gobuster"

if command -v gobuster &>/dev/null || [ -f "$BIN_DIR/gobuster" ]; then
    echo "[=] gobuster already installed – skipping"
else
    wget -q -O gobuster.tar.gz \
    "https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_x86_64.tar.gz"

    tar -xzf gobuster.tar.gz

    chmod +x gobuster

    mv gobuster $BIN_DIR/
fi


echo "[+] Installing gowitness"

if command -v gow &>/dev/null || [ -f "$BIN_DIR/gow" ]; then
    echo "[=] gowitness already installed – skipping"
else
    wget -q -O gow \
    "https://github.com/sensepost/gowitness/releases/download/3.1.1/gowitness-3.1.1-linux-amd64"

    chmod +x gow

    mv gow $BIN_DIR/
fi

echo "[+] Installing google-chrome"

if command -v google-chrome &>/dev/null || command -v google-chrome-stable &>/dev/null; then
    echo "[=] google-chrome already installed – skipping"
else
    wget -q -O chrome.deb \
    "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"

    apt install -y ./chrome.deb
fi


echo "[+] Installing Python libraries"

pip3 install --break-system-packages --ignore-installed --upgrade \
    requests \
    beautifulsoup4 \
    mmh3 \
    cryptography \
    dnspython \
    urllib3 \
    tldextract \
    openai \
    python-dotenv \
    fpdf2


echo "[+] Installing JARM"

if [ -d "/root/RA137/jarm" ]; then
    echo "[=] JARM already cloned – pulling latest"
    cd /root/RA137/jarm
    git pull
else
    echo "[+] Cloning JARM"
    git clone \
    https://github.com/salesforce/jarm.git \
    /root/RA137/jarm
    cd /root/RA137/jarm
fi

pip3 install --break-system-packages --upgrade \
    -r requirements.txt


echo "[+] Updating nuclei templates"

nuclei -update-templates 2>/dev/null || nuclei


echo "[+] Cleaning"

rm -rf $TMP_DIR


echo "[+] Installation completed"