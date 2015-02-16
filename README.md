# libuv-tls
Add SSL/TLS functionality on top of libuv

This small library adds SSL/TLS functionality using BIO pair on libuv.
The TLS work is complete for server but TLS client interface and DTLS support need to be worked on.

### TODO:
- Add session resumption feature
- Renegotiation not yet handled
- Work on supporting DTLS support
- Remove state handling so as to enable multiple, simultaneous client handling
- Fix memory leak in encode_data function



### TEST:
To test the echo server, generate the test cert and key using

```openssl req -x509 -newkey rsa:2048 -nodes -keyout server-key.pem -out server-cert.pem```

```make && ./echo```

Now the echo server is compiled and started and we can start sending some data using

```openssl s_client -connect address:8000 -nbio -state -msg -debug```


where address is your ip address.
