
```echo -n "123456:myname=Qwerty&uid=1001&lstcmd=1" | sha256sum

http://10.9.0.80/?myname=Qwerty&uid=1001&lstcmd=1&download=1&mac=***

gcc length_ext.c -o length_ext -lcrypto

./length_ext

http://10.9.0.80/?myname=Qwerty&uid=1001&lstcmd=1%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%01%30&download=secret.txt&mac=***
```
