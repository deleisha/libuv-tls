echo: test_tls.c
	make -C ./libuv/out
	clang -g -Wall -O2 -o echo test_tls.c uv_ssl.c libuv/out/Debug/libuv.a -lpthread -lssl -lcrypto

clean:echo
	-rm echo
