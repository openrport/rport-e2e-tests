## Initial configuration of the test runner (Ubuntu)

* Install Python (3.8+)
* pip install [paramiko](http://www.paramiko.org/installing.html)
* pip install [pylxd](https://pylxd.readthedocs.io/en/latest/installation.html)
* pip install [websocket-client](https://pypi.org/project/websocket-client/)
* pip install [pyotp](https://github.com/pyauth/pyotp)
* Install lxd: `sudo snap install lxd` [see](https://linuxcontainers.org/lxd/getting-started-cli/)
* Install [snmpget](https://command-not-found.com/snmpget)

Libs for gmail api:

* pip install [google-api-python-client](https://pypi.org/project/google-api-python-client/)
* pip install [oauth2client](https://pypi.org/project/oauth2client/)

#### Configure Lxd and images 
* Initial configuration: `sudo lxd init --auto`
* Add user to ldx group: `sudo usermod -a -G lxd $userName`
* Login to a group: `newgrp lxd` or logout/login the current user in order to see the new group added 
* Verify with the following commands: `lxc list` and `lxc info | more`

* List images: `lxc image list images:`

* Copy images to the local image store

`lxc image copy images:debian/11 local:`

`lxc image copy ubuntu:20.04 local:`

`lxc image copy images:centos/8 local:`

* Verify local image store: `lxc image list`
* Get fingerprints from the output and set them correctly as env variables: `DEBIAN_FINGERPRINT`, `UBUNTU_FINGERPRINT`, `CENTOS_FINGERPRINT`.

#### Environment variable 
You need to set the following environment variables:

```
SSH_PATH=/home/rafal/.ssh/scalewaySSHKey
SSH_PWD=scalewaySSHKeypassword 
GODADDY_API_KEY=
GODADDY_SECRET=
SCALEWAY_SECRET_KEY=
PYLXD_WARNINGS=none
DEBIAN_FINGERPRINT=d5cb788898fd
UBUNTU_FINGERPRINT=fab57376cf04
CENTOS_FINGERPRINT=b4d985c8702e
AUTH_INSTALLER=user:password
```

#### Execute the script - `email2fa.py`

* Run `python3 email2fa.py` to run a stable release
* Run `python3 email2fa.py --unstable` to run an unstable release

* Use `--updates` to check if clients updates are collected. Use `ANY` (default) to wait until any client reports updates, `ALL` to wait for all clients.

#### Execute the script - `totp2fa.py`
* Run `python3 totp2fa.py`

#### Execute the script - `onpremise.py`
* Run `python3 onpremise.py`


#### Lxc - useful commands 

* List instances: `lxc list`
* Log into lxc instance: `lxc exec centos -- sudo /bin/bash`
* Execute command on the instance: `lxc exec instanceName --verbose -- command` ie. `lxc exec ubuntu --verbose -- curl -o rport-installer.sh https://pairing.rport.io/EusXB6`
* Stop/delete instance: `lxc stop centos`, `lxc delete centos`
* Copy file onto instance: `lxc file push myfile.zip instanceName/root/`

