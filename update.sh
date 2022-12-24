git pull
cd resources/kenzer-bin/
git pull
sudo cp * /usr/bin/
cd ../kenzer-templates
git pull
cd ../wapiti
docker build -t wapiti3 .
cd ../wafw00f
docker build -t wafw00f .
cd ../certex-server
docker build -t certex-server .
sudo systemctl restart kenzer.service