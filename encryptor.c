#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <pthread.h>

#define DU_SIZE (1024)


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct
{
	unsigned int ctr;
	unsigned int len;
	int enc;
	uint8_t *xts_key;
	uint8_t *i_buff;
	uint8_t *o_buff;
} thread_ctx;

void* xts_thread(void *arg)
{
	thread_ctx *status = (thread_ctx*)arg;
	int howmany;
	int block;
	uint32_t tweak[4] = {0};
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	const EVP_CIPHER *cipher = EVP_aes_128_xts();
	
	while(1)
	{
		// Lock
		pthread_mutex_lock(&mutex);
		// Check if any data remains
		if(!status->len)
		{
			// If not we can finish the thread
			pthread_mutex_unlock(&mutex);
			EVP_CIPHER_CTX_free(ctx);
			pthread_exit(NULL);
		}
		else
		{
			// Whole block
			if(status->len >= DU_SIZE)
			{
				// Check what is the next block, and update the status
				block = status->ctr;
				status->len -= DU_SIZE;
				status->ctr++;
				// Unlock
				pthread_mutex_unlock(&mutex);
				// Encrypt/Decrypt block
				tweak[0] = block;
				if(!status->enc)
				{
					EVP_EncryptInit_ex(ctx, cipher, NULL, status->xts_key, (uint8_t*)tweak);
					EVP_EncryptUpdate(ctx, &status->o_buff[DU_SIZE*block], &howmany, &status->i_buff[DU_SIZE*block], DU_SIZE);
				}
				else
				{
					EVP_DecryptInit_ex(ctx, cipher, NULL, status->xts_key, (uint8_t*)tweak);
					EVP_DecryptUpdate(ctx, &status->o_buff[DU_SIZE*block], &howmany, &status->i_buff[DU_SIZE*block], DU_SIZE);
				}
			}
			// Last block could be partial
			else
			{
				block = status->ctr;
				howmany = status->len;
				status->len = 0;
				status->ctr++;
				pthread_mutex_unlock(&mutex);
				tweak[0] = block;
				if(!status->enc)
				{
					EVP_EncryptInit_ex(ctx, cipher, NULL, status->xts_key, (uint8_t*)tweak);
					EVP_EncryptUpdate(ctx, &status->o_buff[DU_SIZE*block], &howmany, &status->i_buff[DU_SIZE*block], howmany);
					EVP_EncryptFinal_ex(ctx, &status->o_buff[DU_SIZE*block + howmany], &howmany);
				}
				else
				{
					EVP_DecryptInit_ex(ctx, cipher, NULL, status->xts_key, (uint8_t*)tweak);
					EVP_DecryptUpdate(ctx, &status->o_buff[DU_SIZE*block], &howmany, &status->i_buff[DU_SIZE*block], howmany);
					EVP_DecryptFinal_ex(ctx, &status->o_buff[DU_SIZE*block + howmany], &howmany);
				}					
				EVP_CIPHER_CTX_free(ctx);
				pthread_exit(NULL);
			}
		}
	}
}

int main(int argc, char* argv[])
{
	int i;
	int enc; // 0 = encrypt; 1 = decrypt
	
	int in_fd;
	int out_fd;
	struct stat st;
	int fsize;
	int block = 0;
	
	unsigned char *i_buff, *o_buff;
	
	int threads = 0;
	unsigned char xts_key[16*2] = {0};
	unsigned int tweak[4] = {0}; 
	
	int howmany;
	const EVP_CIPHER *cipher = EVP_aes_128_xts();

	if(6 != argc)
	{
		printf("Invalid nuber of parameters\n");
		printf("Usage:\n");
		printf("%s encrypt|decrypt in key threads out\n", argv[0]);
		goto bail;
	}
	// Check if encrypt or decrypt
	if(!strcmp(argv[1], "encrypt"))
	{
		enc = 0;
	}
	else if(!strcmp(argv[1], "decrypt"))
	{
		enc = 1;
	}
	else
	{
		printf("Invalid first argument, should be encrypt or decrypt\n");
		goto bail;
	}
	// Attempt to open the input file
	if((in_fd = open(argv[2], O_RDONLY)) < 0)
	{
		printf("Error opening the file\n");
		goto bail;
	}
	// File size
	if(fstat(in_fd, &st) < 0)
	{
		printf("Error reading file size\n");
		goto bail;
	}
	fsize = st.st_size;
	// Attempt to create the output file	
	if((out_fd = open(argv[5], O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0)
	{
		printf("Error creating output file\n");
		goto bail;
	}
	if(ftruncate(out_fd, fsize) < 0)
	{
		printf("File truncate error\n");
		goto bail;
	}
	// Memory map for easy access
	i_buff = mmap(0, fsize, PROT_READ, MAP_SHARED, in_fd, 0);
	if (MAP_FAILED == i_buff)
	{
		printf("Input file MMAP error\n");
		goto bail;
	}
	o_buff = mmap(0, fsize, PROT_WRITE, MAP_SHARED, out_fd, 0);
	if (MAP_FAILED == o_buff)
	{
		printf("Output file MMAP error\n");
		goto bail;
	}
	// Set number of threads to use
	threads = atoi(argv[4]);
	if(threads<=0) threads = 1;
	// Prepare the XTS cipher keys, by simply hashing the password
	SHA256(argv[3], strlen(argv[3]), xts_key);
	// Save the overhead when dealing with a single thread
	if(1 == threads)
	{
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		block = 0;
		// Encrypt whole blocks
		while(fsize >= DU_SIZE)
		{
			if(!enc)
			{
				EVP_EncryptInit_ex(ctx, cipher, NULL, xts_key, (uint8_t*)tweak);
				EVP_EncryptUpdate(ctx, &o_buff[DU_SIZE*block], &howmany, &i_buff[DU_SIZE*block], DU_SIZE);
			}
			else
			{
				EVP_DecryptInit_ex(ctx, cipher, NULL, xts_key, (uint8_t*)tweak);
				EVP_DecryptUpdate(ctx, &o_buff[DU_SIZE*block], &howmany, &i_buff[DU_SIZE*block], DU_SIZE);
			}
			block++;
			tweak[0]++;
			fsize-=DU_SIZE;
		}
		// Final partial block
		if(fsize)
		{
			if(!enc)
			{
				EVP_EncryptInit_ex(ctx, cipher, NULL, xts_key, (uint8_t*)tweak);
				EVP_EncryptUpdate(ctx, &o_buff[DU_SIZE*block], &howmany, &i_buff[DU_SIZE*block], fsize);
				EVP_EncryptFinal_ex(ctx, &o_buff[DU_SIZE*block + howmany], &howmany);
			}
			else
			{
				EVP_DecryptInit_ex(ctx, cipher, NULL, xts_key, (uint8_t*)tweak);
				EVP_DecryptUpdate(ctx, &o_buff[DU_SIZE*block], &howmany, &i_buff[DU_SIZE*block], fsize);
				EVP_DecryptFinal_ex(ctx, &o_buff[DU_SIZE*block + howmany], &howmany);
			}
		}
		EVP_CIPHER_CTX_free(ctx);
	}
	// Multi-threaded
	else
	{
		thread_ctx status;
		pthread_t *thread_pool;
		
		if((thread_pool = (pthread_t*)malloc(threads*sizeof(pthread_t))) == NULL)
		{
			printf("MALLOC error\n");
			goto bail;
		}
		
		status.ctr = 0;
		status.len = fsize;
		status.enc = enc;
		status.xts_key = xts_key;
		status.i_buff = i_buff;
		status.o_buff = o_buff;
		
		for(i=0; i<threads; i++) 
		{
			pthread_create(&thread_pool[i], NULL, &xts_thread, &status);
			if(!thread_pool[i]) 
			{
				printf("Thread allocation error\n");
				goto bail;
			}
		}
		
		for(i=0; i<threads; i++)
		{
			pthread_join(thread_pool[i], NULL);
		}
	}
	

bail:
	return 0;	
}
