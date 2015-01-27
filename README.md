# libuv-ssl
Add SSL/TLS functionality on top of libuv

This small library adds SSL/TLS functionality using BIO pair on libuv.
The TLS work is complete for server but TLS client interface and DTLS support need to be worked on.

### TODO:
- Improve error handling - may be introducing our own enum
- Add session resumption feature
- Add code for uv_ssl_connect based on uv_connect
- Improve uv_ssl_shutdown



### TEST:
To test the echo server, generate the test cert snd key using

```openssl req -x509 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem```
