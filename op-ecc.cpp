#include <iostream>
#include <fstream>
#include "miracl.h"
#include "big.h"
#include "ecn.h"
#include <openssl/sha.h>

Miracl precision(48, 16);

#define HASH_LEN 32

Big H1(const char *string)
{ // Hash a zero-terminated string to a number < modulus
    Big h;
    char s[HASH_LEN];
    int i,j,M; 
    sha256 sh;
    shs256_init(&sh);

    for (i=0;;i++)
    {
        if (string[i]==0) break;
        shs256_process(&sh,string[i]);
    }
    shs256_hash(&sh,s);
    // h = from_binary(HASH_LEN, s);
    return h;
}

int main(){
    miracl *mip = &precision;

    // time_t seed;
    // time(&seed);
    // irand((long)seed); /* change parameter for different values */
    irand(2022l); // 置随机种子

    // 椭圆曲线参数读入
    Big a, b, p, q, x, y;
    ECn g;
    int bits;
    ifstream common("common.ecs"); /* construct file I/O streams */
    /* get common data */
    common >> bits;
    mip->IOBASE = 16;
    common >> p >> a >> b >> q >> x >> y;
    // mip->IOBASE = 10;

    ecurve(a, b, p, MR_BEST);
    g = ECn(x, y);            //生成元

    long start, end = 0;
    // Addition Test
    ECn addRes = rand(q) * g;
    for(int i=0; i<1000; i++){
        ECn d = rand(q) * g;
        start = clock();
        addRes += d; 
        end += clock() - start;
    }
    double addAvgTime =  end / 1000.0 / CLOCKS_PER_SEC * 1000.0;

    // Mul Test
    start = end = 0;
    ECn d;
    for(int i=0; i<1000; i++){
        Big k = rand(q);      
        start = clock();
        d = k * g;
        end += clock() - start;
    }
    double mulAvgTime =  end / 1000.0 / CLOCKS_PER_SEC * 1000.0;

    // Hash Test
    start = end = 0;
    
    Big prime;
    for(int i=0; i<1000; i++){
        char str[64] = {0};
        Big k = rand(q);     
        to_binary(k, 64, str);
        start = clock();
        prime = H1(str); 
        end += clock() - start;
    }
    double hashAvgTime =  end / 1000.0 / CLOCKS_PER_SEC * 1000.0;

    // Openssl Hash Test
    start = end = 0;
    for(int i=0; i<1000; i++){
        char str[64] = {0};
        unsigned char res[32];
        Big k = randbits(192);    
        to_binary(k, 64, str);
        start = clock();
        SHA256((unsigned char*)str, 64, res);
        end += clock() - start;
    }
    double sslhashAvgTime =  end / 1000.0 / CLOCKS_PER_SEC * 1000.0;

    printf("[*] Addition Opertion Time: %.6fms\n", addAvgTime);
    printf("[*] Multiplication Opertion Time: %.6fms\n", mulAvgTime);
    printf("[*] Miracl Hash Opertion Time: %.6fms\n", hashAvgTime);
    printf("[*] Openssl Hash Opertion Time: %.6fms\n", sslhashAvgTime);
    return 0;
}