#include <stdio.h>
#include <string.h>
//#include <unistd.h>

#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "C:/Program%20Files%20(x86)/OpenSSL/include/openssl/ossl_typ.h"

/*这个是你自己写的一个十六字节的秘钥,aes加密解密都用这同一个*/
unsigned char key[AES_BLOCK_SIZE] = "123456789abcdef";

#define AES_BITS 10240
#define MSG_LEN 10240

/**********************************************************
函数名：getlen
参数：char *result        --字符串地址
返回值：int                --字符串长度
说明：                    --获取字符串长度
***********************************************************/
int getlen(char* result) {
	int i = 0;
	while (result[i] != '\0') {
		i++;
	}
	return i;
}

/**********************************************************
函数名：aes_encrypt
参数：const char* str_in        --输入字符
参数：unsigned char* key        --key
参数：unsigned char* out        --输出字符
返回值:int                      --0失败  1成功
说明：加密
***********************************************************/
int aes_encrypt(char* str_in, char* out)
{
	if (!str_in || !key || !out) return 0;

	//加密的初始化向量
	unsigned char iv[AES_BLOCK_SIZE];
	//这个也是加密解密同一个确保十六字节里面的内容加密解密一样就ok

	for (int i = 0; i < 16; ++i)
		iv[i] = 0;

	//通过自己的秘钥获得一个aes秘钥以供下面加密使用，128表示16字节
	AES_KEY aes;
	if (AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)
	{
		return 0;
	}

	int len = getlen(str_in);
	//这边是加密接口，使用之前获得的aes秘钥
	AES_cbc_encrypt((unsigned char*)str_in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
	return 1;
}

/**********************************************************
函数名：aes_decrypt
参数：const char* str_in        --输入
参数：unsigned char* key        --key
参数：unsigned char* out        --输出
返回值：int            　　　　　 --0失败  1成功
说明：　　　　　　　　　　　　　　　 --解密
***********************************************************/
int aes_decrypt(char* str_in, char* out)
{
	if (!str_in || !key || !out)
		return 0;

	unsigned char iv[AES_BLOCK_SIZE];
	//这个也是加密解密同一个确保十六字节里面的内容加密解密一样就ok
	for (int i = 0; i < 16; ++i)
		iv[i] = 0;

	//通过自己的秘钥获得一个aes秘钥以供下面解密使用，128表示16字节
	AES_KEY aes;
	if (AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
	{
		return 0;
	}

	int len = getlen(str_in);
	//这边是解密接口，使用之前获得的aes秘钥
	AES_cbc_encrypt((unsigned char*)str_in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
	return 1;
}

//base64加密
int base64_encode(char* in_str, int in_len, char* out_str)
{
	BIO* b64, * bio;
	BUF_MEM* bptr = NULL;
	size_t size = 0;

	if (in_str == NULL || out_str == NULL)
		return -1;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_write(bio, in_str, in_len);
	BIO_flush(bio);

	BIO_get_mem_ptr(bio, &bptr);
	memcpy(out_str, bptr->data, bptr->length);
	out_str[bptr->length] = '\0';
	size = bptr->length;

	BIO_free_all(bio);
	return size;
}

//base64解密
int base64_decode(char* in_str, int in_len, char* out_str)
{
	BIO* b64, * bio;
	BUF_MEM* bptr = NULL;
	int counts;
	int size = 0;

	if (in_str == NULL || out_str == NULL)
		return -1;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bio = BIO_new_mem_buf(in_str, in_len);
	bio = BIO_push(b64, bio);

	size = BIO_read(bio, out_str, in_len);
	out_str[size] = '\0';

	BIO_free_all(bio);
	return size;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("please input origin str\n");
		return 0;
	}
	else
	{
		printf("origin-str:%s\n", argv[1]);
	}

	//aes加密
	char aes_encode_out[30] = { 0 };
	aes_encrypt(argv[1], aes_encode_out);
	printf("aes_encode_out:%s\n", aes_encode_out);

	//base64加密
	char base64_encode_out[1024] = { 0 };
	base64_encode(aes_encode_out, strlen(aes_encode_out), base64_encode_out);
	printf("base64_encode_out:%s\n", base64_encode_out);

	//base64解密
	char base64_decode_out[1024] = { 0 };
	base64_decode(base64_encode_out, strlen(base64_encode_out), base64_decode_out);
	printf("base64_decode_out:%s\n", base64_decode_out);

	//aes解密
	char aes_decode_out[30] = { 0 };
	aes_decrypt(base64_decode_out, aes_decode_out);
	printf("aes_decode_out:%s\n", aes_decode_out);
	return 0;
}



//PyRSAEncrypt

unsigned char* file_data;
struct Path_data* pyc_path = NULL, * head = NULL;

int Add_to_pyc_path(const char* filename)
{
	pyc_path = NULL;
	pyc_path = (struct Path_data*)malloc(sizeof(struct Path_data));
	if (pyc_path == NULL)
		return 1;
	pyc_path->pre = NULL;
	pyc_path->next = NULL;
	strncpy(pyc_path->path, filename, MAX_PATH);
	if (head == NULL)
		head = pyc_path;
	else
	{
		head->pre = pyc_path;
		pyc_path->next = head;
		head = pyc_path;
	}
	return 0;
}

unsigned long get_file_size(const char* path)
{
	unsigned long file_size = -1;
	struct stat stat_buff;
	if (stat(path, &stat_buff) < 0)
	{
		return file_size;
	}
	else
	{
		file_size = stat_buff.st_size;
	}
	return file_size;

}

char* get_private_key_path()
{
	return "/home/etenal/python-2.7/PyRSAEncrypt-master/encrypt_files/private.pem";
}

const char* decrypt(const char* filename) 
{
	const char* path = filename;
	unsigned long file_size = get_file_size(path);
	char decrypted_aes_key[129] = { 0 };
	const int code_length = file_size - 4 - 128 - 16;
	const int aes_offset = 4;
	const int iv_offset = aes_offset + 128;
	const int code_offset = iv_offset + 16;
	char* md5_hash;
	char* md5_return;
	int result;
	unsigned char* de_data;
	int i;
	int de_len = 0;
	int len = 0;

	EVP_CIPHER_CTX* ctx;
	FILE* f = fopen(path, "r");
	if (f == 0)
	{
		return filename;
	}
	file_data = (unsigned char*)malloc(file_size);
	result = fread(file_data, 1, file_size, f);
	if (result != file_size)
	{
		return filename;
	}
	fclose(f);
	if (file_data[0] == 'c' && file_data[1] == 'n' && file_data[2] == 's' && file_data[3] == 's')
	{

		//memcpy(md5_hash,file_data+4,32);
		de_data = (unsigned char*)malloc(file_size);
		memset(de_data, 0, file_size);

		//encrypted aes key -- file_data+36
		//iv -- file_data+164

		/*
		md5 encode

		Verify file integrity

		unsigned char* md5_cal=(unsigned char*)malloc(MD5_DIGEST_LENGTH);
		MD5(file_data+36, file_size-36,md5_cal);
		printf("%c %d\n",file_data+36, file_size-36);
		char* md5_string = (char*)malloc(33);
		memset(md5_string,0,33);
		for(i=0;i<16;i++)
		{
			sprintf(&md5_string[i*2],"%02x",(unsigned int)md5_cal[i]);
		}
		printf("%32s %32s",md5_hash, md5_string);
		if(strncmp(md5_hash,md5_string,32)!=0)
		{
			fprintf(stderr,"file corrupted!");
			free(md5_cal);
			free(md5_string);
			free(file_data);
			free(de_data);
			exit(-1);
			return NULL;
		}
		*/

		/*
		RSA decrypt

		return decrypted_aes_key
		*/
		RSA* rsa;
		char* private_path = get_private_key_path();
		FILE* key_file = fopen(private_path, "rb");
		if (key_file == NULL)
		{
			fprintf(stderr, "open key file failed\n");
			return filename;
		}
		rsa = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
		if (rsa == NULL)
		{
			fprintf(stderr, "read private key failed\n");
			return filename;
		}
		int rsa_len = RSA_size(rsa);
		int aes_len = 0;
		aes_len = RSA_private_decrypt(128, file_data + aes_offset, decrypted_aes_key, rsa, RSA_PKCS1_PADDING);
		if (aes_len < 0)
		{
			fprintf(stderr, "RSA decrypt failed\n");
			RSA_free(rsa);
			return filename;
		}


		/*
		AES decrypt

		return raw code
		*/
		if (!(ctx = EVP_CIPHER_CTX_new()))
		{
			fprintf(stderr, "Initialize AES failed\n");
			return filename;
		}
		if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, decrypted_aes_key, file_data + iv_offset))
		{
			fprintf(stderr, "Decrypt AES failed\n");
			return filename;
		}
		EVP_CIPHER_CTX_set_padding(ctx, 0);

		if (1 != EVP_DecryptUpdate(ctx, de_data, &len, file_data + code_offset, code_length))
		{
			fprintf(stderr, "Decrypt AES failed\n");
			return filename;
		}
		de_len = len;
		if (1 != EVP_DecryptFinal_ex(ctx, de_data + len, &len))
		{
			fprintf(stderr, "Decrypt AES failed\n");
			return filename;
		}
		de_len += len;
		EVP_CIPHER_CTX_free(ctx);
		RSA_free(rsa);
		fclose(key_file);
	}
	else
	{
		return filename;
	}
	f = 0;
	md5_result = malloc(MD5_DIGEST_LENGTH);
	MD5((unsigned char*)filename, strlen(filename), md5_result);
	md5_hash = malloc(33 * sizeof(char));
	md5_return = malloc(40 * sizeof(char));
	for (i = 0; i < 16; i++)
		sprintf(&md5_hash[i * 2], "%02x", (unsigned int)md5_result[i]);
	sprintf(md5_return, "/tmp/%s", md5_hash);
	f = fopen(md5_return, "wb");
	if (f == 0)
	{
		printf("can't output file\n");
		fclose(f);
		free(file_data);
		free(de_data);
		free(md5_hash);
		free(md5_result);
		return filename;
	}
	fwrite(de_data, 1, code_length, f);
	fclose(f);
	free(file_data);
	free(md5_hash);
	free(md5_result);
	memset(de_data, 0, code_length);
	free(de_data);
	return md5_return;
}



/*AES口令*/
char* aes_passwd = NULL;

/*aes解密函数*/

int 
aes_decrypt(wchar_t* filename, const char* aes_passwd, char* plaintext) {

	unsigned long file_size = get_file_size(filename);
	const int aes_offset = 4;
	const int iv_offset = aes_offset + 128;
	const int code_length = file_size;
	int len = 0;
	EVP_CIPHER_CTX* ctx;

	FILE* f = fopen(filename, "r");
	if (f == 0)
	{
		return filename;
	}
	file_data = (unsigned char*)malloc(file_size);

	OpenSSL_add_all_algorithms();

	if (!(ctx = EVP_CIPHER_CTX_new()))
	{
		fprintf(stderr, "Initialize AES failed\n");
		return filename;
	}
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_passwd, file_data + iv_offset))
	{
		fprintf(stderr, "Decrypt AES failed\n");
		return filename;
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, file_data, code_length))
	{
		fprintf(stderr, "Decrypt AES failed\n");
		return filename;
	}
	
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
	{
		fprintf(stderr, "Decrypt AES failed\n");
		return filename;
	}
	EVP_CIPHER_CTX_free(ctx);
	fclose(f);
	return 0;
}


int
rsa_decrypt(wchar_t* filename, char* passwd) {
	char* chkey = rsa_private_key;
	BIO* bp = NULL;
	RSA* rsa_key = RSA_new();
	FILE* file;

	//读取加密秘钥
	if ((file = _Py_wfopen((char*)filename, L"rb")) == NULL) {
		perror("open key file error");
	}
	char str[1024];
	if (fgets(str, 1024, file) != NULL) {
		fprintf(stdout, "open key:%s \n", str);
	}
	fclose(file);

	if ((bp = BIO_new_mem_buf((void*)chkey, -1)) == NULL)
	{
		fprintf(stdout, "BIO_new_mem_buf privateKey error\n");
		return -1;
	}
	OpenSSL_add_all_algorithms();//密钥有经过口令加密需要这个函数
	if ((rsa_key = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, NULL)) == NULL)
	{
		printf("PEM_read_RSAPrivateKey error\n");
		return -1;
	}
	
	PEM_read_bio_RSAPublicKey(bp, &rsa_key, NULL, NULL);
	if (rsa_key == NULL) {
		fprintf(stdout, "PEM_read_bio_RSAPrivateKey failed!\n");
	}

	int rsa_len = RSA_size(rsa_key);
	fprintf(stdout, "RSAPrivateKeylen: %d \n",rsa_len);


	int aes_len = 0;
	char* decrypted_aes_key;
	decrypted_aes_key = malloc(sizeof(char) * (rsa_len + 1));

	aes_len = RSA_private_decrypt(rsa_len, str, decrypted_aes_key, rsa_key , RSA_PKCS1_PADDING);
	if (aes_len < 0)
		fprintf(stdout, "RSA_private_decrypt error\n");
	else
		fprintf(stdout, "RSA_private_decrypt %s\n", decrypted_aes_key);

	return 0;
}