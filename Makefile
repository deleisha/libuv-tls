all: echo 
#tls_client
echo: test_tls.c 
	make -C ./libuv/out
	#clang -fsanitize=address -g -Wall -o echo test_tls.c tls_engine.c uv_tls.c  libuv/out/Debug/libuv.a -lpthread -lssl -lcrypto
	clang -g -Wall -o echo test_tls.c tls_engine.c uv_tls.c  libuv/out/Debug/libuv.a -lpthread -lssl -lcrypto

tls_client: test_tls_client.c
	make -C ./libuv/out
	clang -g -Wall -o tls_client test_tls_client.c uv_tls.c libuv/out/Debug/libuv.a -lpthread -lssl -lcrypto

clean:
	-rm echo
	-rm tls_client
