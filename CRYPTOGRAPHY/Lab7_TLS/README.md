# TASK 1

```docker ps

docker exec -it <-client->  /bin/bash

cd volumes/

ls /etc/ssl/certs | grep -i "AAA"
Comodo_AAA_Services_root.pem

cp /etc/ssl/certs/Comodo_AAA_Services_root.pem ./client-certs/my_root.crt

cd client-certs/

openssl x509 -in my_root.crt -noout -subject_hash
ee64a828

ln -s my_root.crt ee64a828.0

cd ..

python3 handshake.py www.example.com
```

*ON HOST:*

```
dig www.example.com
```

*ON CLIENT:*

```
echo "104.20.23.154 www.example2020.com" >> /etc/hosts

sed -i 's/context.check_hostname = True/# context.check_hostname = True\ncontext.check_hostname = False/' handshake.py
```
*CHEATING:*
```
sed -i "s/ssock = context.wrap_socket(sock, server_hostname=hostname/ # ssock = context.wrap_socket(sock, server_hostname=hostname\nssock = context.wrap_socket(sock, server_hostname='www.example.com'/" handshake.py

python3 handshake.py www.example2020.com
```

# TASK 2

```
cd server-certs/

openssl genrsa -aes256 -out ca.key 2048

openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt

cat <<EOF > server_openssl.cnf
[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extensions = req_ext

[ req_distinguished_name ]
C = US
ST = Wich
L = Kansas
O = StudentLab
CN = www.something.com

[ req_ext ]
subjectAltName = @alt_names

[alt_names]
DNS.1 = www.something.com
DNS.2 = www.example.com
DNS.3 = *.something.com
EOF

openssl req -newkey rsa:2048 -config ./server_openssl.cnf -batch \
-sha256 -keyout server.key -out server.csr

cp /usr/lib/ssl/openssl.cnf ./myopenssl.cnf

sed -i -e 's/organizationName\s*=\s*match/organizationName = optional/' \
       -e 's/# copy_extensions = copy/copy_extensions = copy/' ./myopenssl.cnf

touch demoCA/index.txt

echo 1000 > demoCA/serial

openssl req -newkey rsa:2048 -config ./server_openssl.cnf -batch \
     -sha256 -keyout server.key -out server.csr

openssl ca -md sha256 -days 3650 -config ./myopenssl.cnf -batch \
-in server.csr -out server.crt -cert ca.crt -keyfile ca.key
```

# TASK 3

```
cd server-certs/

docker exec -it  <-server->  /bin/bash

cat <<EOF > target_openssl.cnf
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Wich
O = StudentLab
CN = www.example.com

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = www.example.com
DNS.2 = example.com
EOF

openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout target.key -out target.csr \
    -config target_openssl.cnf

openssl ca -md sha256 -days 365 -config ./myopenssl.cnf -batch \
    -in target.csr -out target.crt \
    -cert ca.crt -keyfile ca.key
    
echo "nameserver 8.8.8.8" > /etc/resolv.conf

cd ..

sudo python3 mitm_proxy.py
```
