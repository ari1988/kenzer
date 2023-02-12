wget  http://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_109.0.5414.119-1_amd64.deb 
sudo dpkg -i google-chrome-stable_109.0.5414.119-1_amd64.deb
wget https://chromedriver.storage.googleapis.com/109.0.5414.74/chromedriver_linux64.zip
unzip chromedriver_linux64.zip
sudo mv chromedriver /usr/bin/chromedriver
chmod +x /usr/bin/chromedriver