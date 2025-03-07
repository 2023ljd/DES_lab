#ifndef _DES_H_
#define _DES_H_

#define ENCRYPTION_MODE 1
#define DECRYPTION_MODE 0

//定义密钥校验位转换方式
#define K56_MODE 1
#define K64_MODE 0

typedef struct {
	unsigned char k[8];
	unsigned char c[4];
	unsigned char d[4];
} key_set;

void generate_key(unsigned char* key);
void generate_sub_keys(unsigned char* main_key, key_set* key_sets);
void process_message(unsigned char* message_piece, unsigned char* processed_piece, key_set* key_sets, int mode);

//自己定义的函数@2023_ljd
void process_input_key(unsigned char* k56, unsigned char* k64, const unsigned char* input_key, short MODE) ;

#endif
