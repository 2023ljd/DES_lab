# DES in C

这是对C实现DES加密标准算法的修改版本，在原版本的加密过程的基础上，增强了控制台对于 密钥/明文/密文 的 输入 / 输出 控制，以便于用户实验调试和展示加密过程。

**注意**：<u>该修改版本是针对 **16进制** 的实验模拟和过程展示</u>

## 实验背景

---

这是修改版本作者在密码分析学课程上的一次实验，起初代码写的很烂，但是由于机缘巧合，很高兴有这样一次机会。通过对初始版本代码的初步了解，对照《分组密码的攻击方法与实例分析》（李超，孙兵，李瑞林著）这本书上关于DES的 加密/解密/密钥扩展 过程，然后加入部分代码，更好地展现了在 cmd 上进行实验的直观性。

## 运行&调试环境建议

---

这份代码可以顺利通过cmd控制台（基于Windows操作系统）实现实验过程的展示，当然，原作者指定使用Linux终端可以实现相应过程，因而可以推断其对Linux的一些Shell的兼容性。

基于现有文件结构，可以在 ``DES-master`` 子文件夹中，调用如下命令：

1. Windows操作系统（使用cmd）：

    1. 生成可以在终端中执行的 .o 文件（给出的文件已经生成过，重复生成没有影响）：

        ```shell
        gcc -O3 des.c run_des.c -o run_des.o
        ```

    2. 给定（16进制）56位/64位种子密钥并保存：

        ```shell
        .\run_des.o -g .\tmp\keyfile.key
        ```

    3. 给定（16进制）明文，使用已经生成过的种子密钥，生成密文并保存:

        ```shell
        .\run_des.o -e .\tmp\keyfile.key .\tmp\sample.txt .\tmp\sample.enc
        ```

    4. 给定（16进制）密文，使用已经生成过的种子密钥，生成明文并保存:

        ```shell
        .\run_des.o -d .\tmp\keyfile.key .\tmp\sample.enc .\tmp\sample_decrypted.txt
        ```

 2. Linux 终端用户：

    通过简单转换，上面的指令也可使用（将\转换为/）,详见`DES-master`子文件夹的`readme`

	###### 注意：	如果出现乱码，请使用`UTF-8`编码（Active code page: 65001）

## 修改版特性

---

1. 对于所有的输入/输出过程，都添加了中文版指引
2. 为源码添加了中文注释，使得相关过程更加清晰明了
3. 注释掉了随机密钥生成函数generate_key的调用,增加了用于加减校验位的种子密钥转换函数process_input_key
4. 针对16进制的实验过程展示（TEST VECTORS），包括：
    1. 提供密钥时判断56位/64位，并反馈16进制的56位密钥和64位密钥，位数不符时报错
    2. 加密/解密时给出每轮的子密钥，以及分组展示每轮加密/解密时的中间过程
5. 实验结果的反馈，最后均会反馈从相应文件中读出的 明文 和 密文 组合
6. 输入的16进制字符不区分大小写，并且会过滤非0~9、A(a)~F(f)的字符
7. 在终端输入的信息，均会转换成字符，以二进制模式存入相应文件

## 鸣谢

---

原作者的github源码： http://github.com/tarequeh/DES/ 

理论来源（为理解源码提供理论支持）:《分组密码的攻击方法与实例分析》（李超，孙兵，李瑞林著）

合作者：[ASSASSINs2066 (grimner)](https://github.com/ASSASSINs2066)

​		[2023ljd](https://github.com/2023ljd)

期待发现和使用，欢迎提出建议！