echo: tls.c
	make -C libuv/out
	clang -g -o echo tls.c uv_ssl.c libuv/out/Debug/libuv.a -lpthread -lssl -lcrypto

clean:echo
	-rm echo
