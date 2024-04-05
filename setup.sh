#!/bin/bash
#For Linux Environment
#Setup github
cd ~
mkdir workspace 2> /dev/null
cd workspace
ssh-keygen -t rsa -b 4096 -q -N "" -f /home/$USER/.ssh/id_rsa
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install -y gh
gh auth login --hostname github.com --git-protocol https

#Download scanners
cd ~/workspace
gh repo clone https://github.com/klsecservices/s7scan.git
sudo pip3 install python-snap7 pymodbustcp pycomm3==1.2.6
sudo apt update
sudo apt install -y crowbar vim python2.7 htop openssh-server seclists postgresql git remmina eyewiteness proxychains4
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
python2.7 get-pip.py
python2.7 -m pip install makerlib distribute scapy
pushd .;cd /usr/share/nmap/scripts;sudo wget https://gist.githubusercontent.com/littleairmada/b04319742c29efe44d5662d842c20e1c/raw/c500449760e7a97f780d0b3627dac37823168a00/banner-plus.nse;popd
cd ~/workspace
gh repo clone https://github.com/digitalbond/Redpoint.git;cd Redpoint
sudo gem install modbus-cli
cd ~/workspace
gh repo clone https://github.com/theralfbrown/smod-1.git
