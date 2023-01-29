git pull
pip3 install -U -r requirements.txt
cd resources/kenzer-bin/
git pull
sudo cp * /usr/bin/
cd ../kenzer-templates
git pull
cd ../wapiti
sudo docker build -t wapiti3 .
cd ../wafw00f
sudo docker build -t wafw00f .
cd ../certex-server
sudo docker build -t certex-server .
sudo systemctl restart kenzer.service