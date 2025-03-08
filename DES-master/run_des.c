#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * des.h provides the following functions and constants:
 *
 * generate_key, generate_sub_keys, process_message, ENCRYPTION_MODE, DECRYPTION_MODE
 *
 * additionally: process_input_key
 */
#include "des.h"

// Declare file handlers
static FILE *key_file, *input_file, *output_file;

// Declare action parameters
#define ACTION_GENERATE_KEY "-g"
#define ACTION_ENCRYPT "-e"
#define ACTION_DECRYPT "-d"

// DES key is 8 bytes long
#define DES_KEY_SIZE 8

int main(int argc, char* argv[]) {
	clock_t start, finish;
	double time_taken;
	unsigned long file_size;
	unsigned short int padding;

	if (argc < 2) {
		printf("You must provide at least 1 parameter, where you specify the action.");
		return 1;
	}

	if (strcmp(argv[1], ACTION_GENERATE_KEY) == 0) { // Generate key file
		if (argc != 3) {
			printf("Invalid # of parameter specified. Usage: run_des -g keyfile.key");
			return 1;
		}

		key_file = fopen(argv[2], "w");
		if (!key_file) {
			printf("Could not open file to write key.");
			return 1;
		}

		unsigned int iseed = (unsigned int)time(NULL);
		srand (iseed);

		short int bytes_written;
		unsigned char* des_key = (unsigned char*) malloc(8*sizeof(char));
		
		
		//generate_key(des_key);
		//注释掉随机密钥生成函数，改为控制台输入并修改形式，传给des_key
		//============================
		unsigned char *k56 ,/* *k64 , */*input_key ;
		k56 = (unsigned char*)malloc(8*sizeof(char)) ;
		//k64 = (unsigned char*)malloc(8*sizeof(char)) ;
		input_key = (unsigned char*)malloc(200*sizeof(char)) ;
		memset(k56 , 0 , sizeof(k56) ) ;
		//memset(k64 , 0 , sizeof k64) ;
		memset(input_key,0,sizeof(input_key)) ;
		memset(des_key , 0 , sizeof des_key) ;
		printf("\n\t请输入 种子密钥 (十六进制,56 bit/64 bit):\t") ;
		char c=getchar() ;	
		int num_of_char=0 ;
		unsigned char hex=0 ;
		while(c!='\n')	{
			if(c>='0'&&c<='9') {
				hex = c-'0' ;
			}else if(c>='A'&&c<='Z') {
				hex = c-'A'+10 ;
			}else if(c>='a'&&c<='z') {
				hex = c-'a'+10 ;
			}else {
				c = getchar() ;
				continue ;
			}
			input_key[num_of_char>>1] |= hex<<(num_of_char&1 ? 0 : 4) ;
			num_of_char++ ;
			c = getchar() ;
		}
		if(num_of_char == 14 ) {
			printf("\n\t已检测到56位密钥." , K56_MODE) ;
			process_input_key(k56,des_key, input_key, K56_MODE) ;
		}else if(num_of_char == 16) {
			printf("\n\t已检测到64位密钥." , K64_MODE) ;
			process_input_key(k56,des_key, input_key, K64_MODE) ;
		}else {
			printf("\t密钥长度错误!\n\n") ;
			return 1 ;
		}

		free(input_key) ;

		//控制台输出k56、des_key
		printf("\n\n\t存入的种子密钥为:\n") ;
		printf("\t\t56 bit:\t") ;
		for(int i=0 ; i<7 ; i++)
			printf("%02X " , k56[i]) ;
		printf("\n\t\t64 bit:\t") ;
		for(int i=0 ; i<8 ; i++)
			printf("%02X " , des_key[i]) ;
		printf("\n") ;

		free(k56) ;
		//============================


		bytes_written = fwrite(des_key, 1, DES_KEY_SIZE, key_file);
		if (bytes_written != DES_KEY_SIZE) {
			printf("Error writing key to output file.");
			fclose(key_file);
			free(des_key);
			return 1;
		}

		free(des_key);
		fclose(key_file);
	} else if ((strcmp(argv[1], ACTION_ENCRYPT) == 0) || (strcmp(argv[1], ACTION_DECRYPT) == 0)) { // Encrypt or decrypt
		if (argc != 5) {
			printf("Invalid # of parameters (%d) specified. Usage: run_des [-e|-d] keyfile.key input.file output.file", argc);
			return 1;
		}

		// Read key file
		key_file = fopen(argv[2], "rb");
		if (!key_file) {
			printf("Could not open key file to read key.");
			return 1;
		}

		short int bytes_read;
		unsigned char* des_key = (unsigned char*) malloc(8*sizeof(char));
		bytes_read = fread(des_key, sizeof(unsigned char), DES_KEY_SIZE, key_file);
		if (bytes_read != DES_KEY_SIZE) {
			printf("Key read from key file does nto have valid key size.");
			fclose(key_file);
			return 1;
		}
		fclose(key_file);

		// Open output file
		output_file = fopen(argv[4], "wb");// 增加了output_file的读属性,先写后读***
		if (!output_file) {
			printf("Could not open output file to write data.");
			return 1;
		}

		// Open input file
		input_file = fopen(argv[3], "wb"); // 增加了input_file的写属性,先写后读***
		if (!input_file) {
			printf("Could not open input file to write data.");
			return 1;
		}

		
		//增加控制台获取十六进制明文or密文，转换为字符并存进input_file的过程
		//==============================
		unsigned char *input_info = (unsigned char *)malloc(200*sizeof(char));
		memset(input_info,0,sizeof(input_info)) ;
		printf("\n\t请输入 明文(-e)或密文(-d) (16进制):\t") ;
		char c = getchar() ;
		unsigned char hex , num_of_char=0 ;
		while(c!='\n') {
			if(c>='0'&&c<='9') {
				hex = c-'0' ;
			}else if(c>='A'&&c<='Z') {
				hex = c-'A'+10 ;
			}else if(c>='a'&&c<='z') {
				hex = c-'a'+10 ;
			}else {
				c = getchar() ;
				continue ;
			}
			input_info[num_of_char>>1] |= (unsigned char)(hex<<(num_of_char&1 ? 0 : 4)) ;
			num_of_char++ ;
			c = getchar() ;
		}

		fwrite(input_info, 1, (num_of_char+1)>>1, input_file) ;
		free(input_info) ;
		fclose(input_file) ;//关闭input_file的写入,准备读取
		// Open input file
		input_file = fopen(argv[3], "rb"); // 增加了input_file的写属性,先写后读
		if (!input_file) {
			printf("Could not open input file to read data.");
			return 1;
		}
		//=============================


		// Generate DES key set
		short int bytes_written, process_mode;
		unsigned long block_count = 0, number_of_blocks;
		unsigned char* data_block = (unsigned char*) malloc(8*sizeof(char));
		unsigned char* processed_block = (unsigned char*) malloc(8*sizeof(char));
		key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));

		start = clock();
		generate_sub_keys(des_key, key_sets);//生成1~16轮子密钥
		finish = clock();
		time_taken = (double)(finish - start)/(double)CLOCKS_PER_SEC;


		//输出Test Vectors的第1部分：每轮加密的子密钥
		//================================
		printf("\n\n\tTEST VECTORS\n\t========================================================================\n\n") ;
		printf("\t下面是生成的16轮子密钥.\n\n") ;
		for(int i=1 ; i<=16 ; i++){
			printf("\t\t第%02d轮子密钥k[%02d]:\t", i, i) ;
			for(int j=0 ; j<8 ; j++)
				printf("%02X " , key_sets[i].k[j]) ;
			printf("\n") ;
		}
		printf("\n") ;
		//=================================


		// Determine process mode
		if (strcmp(argv[1], ACTION_ENCRYPT) == 0) {
			process_mode = ENCRYPTION_MODE;
			//printf("Encrypting..\n");
		} else {
			process_mode = DECRYPTION_MODE;
			//printf("Decrypting..\n");
		}//注释掉冗余信息***

		// Get number of blocks in the file
		fseek(input_file, 0L, SEEK_END);
		file_size = ftell(input_file);

		fseek(input_file, 0L, SEEK_SET);
		number_of_blocks = file_size/8 + ((file_size%8)?1:0);//明文一共有几组？

		start = clock();

		// Start reading input file, process and write to output file
		while(fread(data_block, 1, 8, input_file)) {//读接下来还有没有没读的内容
			block_count++;
			if (block_count == number_of_blocks) {//最后一组（可能长度不够）
				if (process_mode == ENCRYPTION_MODE) {//最后一组的编码过程
					padding = 8 - file_size%8;
					if (padding < 8) { // Fill empty data block bytes with padding
						memset((data_block + 8 - padding), (unsigned char)padding, padding);
					}

					process_message(data_block, processed_block, key_sets, process_mode);
					bytes_written = fwrite(processed_block, 1, 8, output_file);

					if (padding == 8) { // Write an extra block for padding（不是很理解，可能是规定？）
						memset(data_block, (unsigned char)padding, 8);
						process_message(data_block, processed_block, key_sets, process_mode);
						bytes_written = fwrite(processed_block, 1, 8, output_file);
					}
				} else {//最后一组的解码过程
					process_message(data_block, processed_block, key_sets, process_mode);
					padding = processed_block[7];

					if (padding < 8) {
						bytes_written = fwrite(processed_block, 1, 8 - padding, output_file);
					}
				}
			} else {//不是最后一组
				process_message(data_block, processed_block, key_sets, process_mode);
				bytes_written = fwrite(processed_block, 1, 8, output_file);
			}
			memset(data_block, 0, 8);
		}


		//=========================
		fclose(output_file) ;//关闭output_file的写属性，准备开启读属性
		// Open output file
		output_file = fopen(argv[4], "rb");// 增加了output_file的读属性,先写后读
		if (!output_file) {
			printf("Could not open output file to read data.");
			return 1;
		}
		fseek(input_file , 0 , SEEK_SET) ;//input_file重新指向文件开头

		//前面的处理过程中加入  轮密钥、每轮处理结果  (Test Vectors)
		//加入的控制台最后输出部分：加密/解密 , 输入info , 输出info ; 
		unsigned char *get_info = (unsigned char*)malloc(sizeof(char)*1) ;
		if(strcmp(argv[1], ACTION_ENCRYPT) == 0) {
			printf("\n\t=======================================================================\n\t加密 过程结束.\n\n") ;
			printf("\t\t 明文(待处理数据):\t") ;
			while(fread(get_info,1,1,input_file)) {
				printf("%02X " , *get_info) ;
			}
			printf("\n\t\t 密文(处理结果):\t") ;
			while(fread(get_info,1,1,output_file)) {
				printf("%02X " , *get_info) ;
			}
		}else {
			printf("\n\t=======================================================================\n\t解密 过程结束.\n\n") ;
			printf("\t\t 密文(待处理数据):\t") ;
			while(fread(get_info,1,1,input_file)) {
				printf("%02X " , *get_info) ;
			}
			printf("\n\t\t 明文(处理结果):\t") ;
			while(fread(get_info,1,1,output_file)) {
				printf("%02X " , *get_info) ;
			}
		} 
		printf("\n\t=======================================================================\n\n") ;
		//========================

		finish = clock();

		// Free up memory
		free(des_key);
		free(data_block);
		free(processed_block);
		fclose(input_file);
		fclose(output_file);

		// Provide feedback
		time_taken = (double)(finish - start)/(double)CLOCKS_PER_SEC;
		printf("Finished processing %s. Time taken: %lf seconds.\n", argv[3], time_taken);
		return 0;
	} else {
		printf("Invalid action: %s. First parameter must be [ -g | -e | -d ].", argv[1]);
		return 1;
	}

	return 0;
}
