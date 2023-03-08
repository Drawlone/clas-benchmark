#include "include/clas.h"
#include <fstream>
#include <sstream>

Miracl precision(196, 16);
miracl *mip = &precision;
ECn g, Pub;
Big q, alpha;

void setup(){
    // 椭圆曲线参数读入
    Big a, b, p, px, py;
    int bits;
    ifstream common("common.ecs"); /* construct file I/O streams */
    /* get common data */
    common >> bits;
    mip->IOBASE = 16;
    common >> p >> a >> b >> q >> px >> py;

    ecurve(a, b, p, MR_BEST);
    g = ECn(px, py);            //生成元
    alpha = rand(q);
    Pub = alpha * g;
}

Big Hash(stringstream &st){
    size_t size = st.tellp();
    char* buff = new char[size];
    st.read(buff, size);
    unsigned char value[HASH_LEN];
    SHA256((unsigned char *)buff, size, value);
    st.str("");
    delete[] buff;
    return from_binary(HASH_LEN, (char *)value);
}





void aggTest(Clas& clas, int n){

}