all:b64openssl

b64openssl:
		gcc -o b64encdecode main.c -I. -lcrypto -DUSED_OPENSSL
b64mbedtls:
		gcc -o b64encdecode main.c -I. -lmbedcrypto -lmbedtls -DUSED_MBEDTLS

clean:
	rm -f b64encdecode
