echo: tls.c
	clang -g tls.c -I ../TackleBio/ ../TackleBio/libuv/out/Debug/libuv.a -lpthread -lssl -lcrypto

clean:echo
	-rm echo
