#pragma once
#include <fstream>
#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>//大数产生
#include <boost/multiprecision/random.hpp>//随机数产生
#include <boost/multiprecision/miller_rabin.hpp>//素性检测

#define NUM 20
namespace bordm = boost::random;

/*
	1.产生两个素数
	2.计算n
	3.计算f(n)
	4.从1 < e < f(n)中挑选一个与f(n)互质的数e
	5.求e对于f(n)的模反元素(逆元)d
	6.公钥：(e,n)
	7.私钥：(d,n)
*/

//高精度的一个位数为1024位的数字类型
typedef boost::multiprecision::int1024_t DataType;


struct KEY
{
	DataType m_ekey;
	DataType m_dkey;
	DataType m_pkey;
};

class RSA
{
	KEY m_key;
	void Key();//生成公钥、私钥
	
	DataType Prime();//得到素数 ※
	DataType Pkey(DataType prime1, DataType prime2);//计算n
	DataType Orla(DataType p, DataType q);//计算f(n)
	DataType Ekey(DataType orla);//计算公钥e ※
	DataType Dkey(DataType orla, DataType ekey);//计算私钥d ※
	DataType ecrept(DataType data, DataType ekey, DataType pkey);//※
	DataType decrept(DataType data, DataType dkey, DataType pkey);
	bool isPrimeBigInt(DataType data);//判断一个数是不是素数 ※
	DataType getGcd(DataType data1, DataType data2);//辗转相除法求最大公约数(欧几里得算法)
	DataType exGcd(DataType a, DataType b, DataType& x, DataType& y);//扩展的欧几里得算法 ※
public:
	RSA()
	{
		Key();
	}
	KEY GetAllkey();
	void EncryptionFile(const char * filename, const char * fileout);//对文件进行分块加密
	void DecryptFile(const char * filename, const char * fileout);//对文件进行分块解密
};

