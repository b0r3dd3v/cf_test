all:
	gcc -O3 encryptor.c -lcrypto -lpthread -o encryptor
