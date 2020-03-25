#include "rsa.h"
#include <iostream>

using namespace std;


void test()
{
	RSA rsa;
	KEY key = rsa.GetAllkey();
	cout << "e = " << key.m_ekey << endl;
	cout << "d = " << key.m_dkey << endl;
	rsa.EncryptionFile("test.txt", "test.ecrept.txt");
	rsa.DecryptFile("test.ecrept.txt", "test.decrept.txt");
}


int main()
{

	test();
	cout << "finish!" << endl;
	return 0;
}
