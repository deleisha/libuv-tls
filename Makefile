all: echo tls_client gen_cert
echo: test_tls.c 
	cd libuv && python gyp_uv.py
	make -C ./libuv/out
	#clang -fsanitize=address -g -Wall -o echo test_tls.c tls_engine.c uv_tls.c  libuv/out/Debug/libuv.a -lpthread -lssl -lcrypto
	clang -g -Wall -Wunused -o $@ tls_engine.c uv_tls.c  test_tls.c \
            libuv/out/Debug/libuv.a -ldl -lrt -lpthread -lssl -lcrypto 

tls_client: test_tls_client.c
	cd libuv && python gyp_uv.py
	make -C ./libuv/out
	clang -g -Wall -o $@ tls_engine.c uv_tls.c test_tls_client.c \
            libuv/out/Debug/libuv.a -ldl -lrt -lpthread -lssl -lcrypto

new:
	cd libuv && python gyp_uv.py
	make -C ./libuv/out
	clang -g -Wall -o $@ new.c libuv/out/Debug/libuv.a -ldl -lrt -lpthread -lssl -lcrypto



gen_cert:
	openssl req -x509 -newkey rsa:2048 -nodes -keyout server-key.pem -out server-cert.pem -config ssl_test.cnf

clean:
	-rm echo
	-rm tls_client
	-rm new
