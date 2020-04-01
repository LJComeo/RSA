#include "rsa.h"

void RSA::Key()
{
	DataType prime1 = Prime();
	DataType prime2 = Prime();

	while (prime1 == prime2)
	{
		prime2 = Prime();
	}
	DataType orla = Orla(prime1, prime2);//f(n)
	m_key.m_pkey = Pkey(prime1, prime2);//n
	m_key.m_ekey = Ekey(orla);//e
	m_key.m_dkey = Dkey(orla, m_key.m_ekey);//d
}

KEY RSA::GetAllkey()
{
	return m_key;
}

void RSA::EncryptionFile(const char * filename, const char * fileout)//对文件进行分块加密
{
	std::ifstream fin(filename, std::ifstream::binary);//以二进制写入形式打开一个文件
	std::ofstream fout(fileout, std::ofstream::binary);//以二进制读出形式打开一个文件
	if (!fin.is_open())
	{
		perror("input file open failed!\n");
		return;
	}
	char* buffer = new char[NUM];
	DataType* bufferout = new DataType[NUM];
	while (!fin.eof())
	{
		fin.read(buffer, NUM);//将fin中的数据读到buffer中
		int curNum = fin.gcount();
		for (int i = 0; i < curNum; i++)
		{
			bufferout[i] = ecrept(buffer[i], m_key.m_ekey, m_key.m_pkey);
		}
		fout.write((char*)bufferout, curNum * sizeof(DataType));
	}
	delete[] bufferout;
	delete[] buffer;
	
	fin.close();
	fout.close();
}
void RSA::DecryptFile(const char * filename, const char * fileout)//对文件进行分块解密
{
	std::ifstream fin(filename, std::ifstream::binary);//以二进制写入形式打开一个文件
	std::ofstream fout(fileout, std::ofstream::binary);//以二进制读出形式打开一个文件
	if (!fin.is_open())
	{
		perror("file open failed!\n");
		return;
	}
	DataType* buffer = new DataType[NUM];

	char* bufferout = new char[NUM];
	while (!fin.eof())
	{
		fin.read((char*)buffer, NUM * sizeof(DataType));//将fin中的数据读到buffer中
		int num = fin.gcount();
		num /= sizeof(DataType);
		for (int i = 0; i < num; i++)
		{
			bufferout[i] = (char)decrept(buffer[i], m_key.m_dkey, m_key.m_pkey);
		}
		fout.write(bufferout, num);
	}
	delete[] bufferout;
	delete[] buffer;
	
	fin.close();
	fout.close();
}
DataType RSA::Prime()//得到素数 ※
{
	bordm::mt19937 Gen(time(nullptr));//随机数发生器
	bordm::uniform_int_distribution<DataType> Breadth(0, DataType(1) << 128);//随机数的范围
	DataType prime;
	while (true)
	{
		prime = Breadth(Gen);
		if (isPrimeBigInt(prime))
			break;
	}
	return prime;
}
DataType RSA::Pkey(DataType prime1, DataType prime2)//计算n
{
	return prime1 * prime2;
}
DataType RSA::Orla(DataType p, DataType q)//计算f(n)
{
	return (p - 1) * (q - 1);
}
DataType RSA::Ekey(DataType orla)//计算公钥e ※
{
	bordm::mt19937 Gen(time(nullptr));
	bordm::uniform_int_distribution<DataType> dist(2, orla);
	DataType ekey;
	while (true)
	{
		ekey = dist(Gen);
		if (getGcd(orla, ekey) == 1)
			return ekey;
	}
}
bool RSA::isPrimeBigInt(DataType data)//判断一个数是不是素数 ※
{
	bordm::mt11213b gen(time(nullptr));
	if (miller_rabin_test(data, 25, gen))
	{
		if (miller_rabin_test((data - 1) / 2, 25, gen))//0.25的25次方的可能是错误的
		{
			return true;
		}
	}
	return false;
}
DataType RSA::Dkey(DataType orla, DataType ekey)//计算私钥d ※
{
	DataType x = 0, y = 0;
	exGcd(ekey, orla, x, y);
	return (x % orla + orla) % orla;
}
DataType RSA::getGcd(DataType data1, DataType data2)//辗转相除法求最大公约数(欧几里得算法)
{
	DataType ret;
	while (ret = data1 % data2)
	{
		data1 = data2;
		data2 = ret;
	}
	return data2;
}
DataType RSA::exGcd(DataType a, DataType b, DataType& x, DataType& y)//扩展的欧几里得算法 ※
{
	if (b == 0)
	{
		x = 1;
		y = 0;
		return a;
	}
	DataType gcd = exGcd(b, a % b, x, y);
	DataType x1 = x, y1 = y;
	x = y1;
	y = x1 - a / b * y1;
	return gcd;
}
DataType RSA::ecrept(DataType data, DataType ekey, DataType pkey)//加密过程的模幂运算:蒙哥马利算法※
{
	DataType a = data;
	DataType tmp = 1;
	while (ekey)
	{
		if (ekey & 1)
			tmp = (tmp * a) % pkey;
		ekey >>= 1;
		a = (a * a) % pkey;
	}
	return tmp;
}
DataType RSA::decrept(DataType data, DataType dkey, DataType pkey)
{
	return ecrept(data, dkey, pkey);
}