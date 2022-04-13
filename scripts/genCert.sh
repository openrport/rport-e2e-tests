cd sc
touch ~/.rnd
openssl req -newkey rsa:2048 -nodes -keyout lxd.key -out lxd.csr -subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=client/CN=`hostname -f`/emailAddress=e2e@rport.io"
openssl x509 -signkey lxd.key -in lxd.csr -req -days 365 -out lxd.crt
cat lxd.key lxd.crt > lxd.pem