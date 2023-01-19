chmod +x *.sh
sudo apt update
sudo apt install optipng moreutils openjdk-11-jre-headless jq unzip nmap docker.io xsltproc python3 python3-pip libpangocairo-1.0-0 libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 libxi6 libxtst6 libnss3 libcups2 libxss1 libxrandr2 libasound2 libatk1.0-0 libgtk-3-0 libgbm-dev libxshmfence-dev
pip3 install --upgrade pip
pip3 install --ignore-installed PyYAML
mkdir resources
git clone https://github.com/ARPSyndicate/kenzerdb.git
cd kenzerdb
git config --global http.postBuffer 1048576000
git config --global ssh.postBuffer 1048576000
cd ..
cd resources
if getopts "b" arg; then
  bash ../chrome.sh
  git clone https://github.com/ARPSyndicate/kenzer-bin.git
  git clone https://github.com/wapiti-scanner/wapiti.git
  cd wapiti
  docker build -t wapiti3 .
  cd ..
  git clone https://github.com/EnableSecurity/wafw00f.git
  cd wafw00f
  docker build -t wafw00f .
  cd ..
  git clone https://github.com/ARPSyndicate/certex-server.git
  cd certex-server
  docker build -t certex-server .
  cd ..
  sudo cp kenzer-bin/* /usr/bin/
  wget https://github.com/zaproxy/zaproxy/releases/download/v2.12.0/ZAP_2_12_0_unix.sh
  bash ZAP_2_12_0_unix.sh
fi
git clone https://github.com/ARPSyndicate/kenzer-templates.git
cd ..
pip3 install -U -r requirements.txt
mkdir ~/.config
mkdir ~/.config/subfinder
mkdir ~/.config/uncover
cp configs/subfinder.yaml ~/.config/subfinder/provider-config.yaml
cp configs/uncover.yaml ~/.config/uncover/provider-config.yaml
cp configs/amass.ini ~/.config/amass-config.ini
cp configs/waymore.yml ~/.waymore-config.yml
./run.sh