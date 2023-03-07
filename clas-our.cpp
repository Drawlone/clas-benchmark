#include <iostream>
#include <fstream>
#include "include/miracl.h"
#include "include/big.h"
#include "include/ecn.h"
#include <openssl/sha.h>

// g++ -O3 clas.cpp ecn.cpp miracl.a -lcrypto  -o clas

Miracl precision(196, 16);

#define HASH_LEN 32

struct Sig
{
    ECn U;
    Big s;
};

Big Hash(void* data, size_t len){
    unsigned char value[HASH_LEN];
    SHA256((const unsigned char*)data, len, value);
    return from_binary(HASH_LEN, (char *)value);
}

class OurCLAS{
private:
    void init(miracl *mip){
        // 椭圆曲线参数读入
        Big a, b, p, px, py;
        int bits;
        ifstream common("common.ecs"); /* construct file I/O streams */
        /* get common data */
        common >> bits;
        mip->IOBASE = 16;
        common >> p >> a >> b >> q >> px >> py;
        // mip->IOBASE = 10;

        ecurve(a, b, p, MR_BEST);
        g = ECn(px, py);            //生成元
    }

public:
    OurCLAS(miracl *mip){
        init(mip);
    }

    void setup(){      
        x = rand(q);
        alpha = rand(q);
        r = rand(q);
        X = x * g, R = r * g, Pub = alpha * g;
        pid = PID{eta*g, randbits(256)};
        cout << "PK: {" << X << ", " << R << "}" << endl;

        h1_struct = H1{pid, R, Pub};        
        Big h1 = Hash(&h1_struct, sizeof(H1));
        d = r + alpha * h1;
        cout << "sk: {" << x << ", " << d << "}" << endl;

    }

    Sig sign(){        
        Big u = rand(q);
        ECn U = u * g;
        long t = clock();
        h2_struct = H2{pid, X, R, U, t};
        h3_struct = H3{pid, U};

        Big h2 = Hash(&h2_struct, sizeof(H2)), h3 = Hash(&h3_struct, sizeof(H3));

        Big s = u + x * h3 + d * h2;
        return Sig{U, s};
    }

    bool verify(Sig sig, ECn& left, ECn& right){
        // suppose we have received PID, PK, T, m and s
        Big h1 = Hash(&h1_struct, sizeof(H1));
        Big h2 = Hash(&h2_struct, sizeof(H2));
        Big h3 = Hash(&h3_struct, sizeof(H3));
        left = sig.s * g;
        right = h1 * Pub;
        right += R;
        right *= h2;
        right += h3 * X;
        right += sig.U;
        if(left == right) 
            return true;
        return false;
    }
private:
    ECn g, X, R, Pub;
    Big q, x, alpha, r, d, eta;
    struct PID
    {
        ECn pid1;
        Big pid2;
    } pid;

    struct H1
    {
        PID pid;
        ECn R;
        ECn Pub;
    } h1_struct;  

    struct H2
    {
        PID pid;
        ECn X;
        ECn R;
        ECn U;
        long T;
    } h2_struct;

    struct H3
    {
        PID pid;
        ECn U;
    } h3_struct;

};




int main(){
    miracl *mip = &precision;
    long start;
    double diff;
    Sig sig;
    ECn left, right;
    irand(2022l); // 置随机种子

    
    cout << "First, we generate public key and scret key!" << endl;
    OurCLAS ourclas(mip);
    ourclas.setup();

    cout << "\nThen we compute the signature." << endl;
    start = clock();
    sig = ourclas.sign();
    diff = ((double)clock() - start)/ CLOCKS_PER_SEC * 1000.0;
    cout << "Sig: {" << sig.U << ", " << sig.s << "}" << endl;
    printf("[*] Sign Time: %.6fms\n", diff);

    cout << "\nNow, we start to verify the sig." << endl;
    start = clock();
    if(ourclas.verify(sig, left, right)){
        diff = ((double)clock() - start)/ CLOCKS_PER_SEC * 1000.0;
        cout << "left: \t" << left << endl;
        cout << "right: \t" << right << endl;
        printf("[*] ACCEPT! Verification Time: %.6fms\n", diff);
    }

    return 0;
}