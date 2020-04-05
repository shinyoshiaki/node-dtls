```sh
openssl s_client -connect 127.0.0.1:4433 -dtls1_2
openssl s_server -accept 4433 -key server.pem -cert server.pem -dtls1_2
```
