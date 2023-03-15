#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <openssl/sha.h>

#define MR_PAIRING_SSP   
// #define MR_PAIRING_SS2	
// a super-singular curve over GF(p) implents Tate pairing
// p = B83DFB800C851836F9B95087F2642EF80B044116A536A5D5C35F02A297B82515F98C5E7D90AE1524653D8298402F5F35AE20D87A03E791E8DC6C070D564EC663

#define AES_SECURITY 80  // AES-80 security
#define HASH_LEN 32
#include "pairing_1.h"

PFC pfc(AES_SECURITY);
Big s;
G1 P, Pub;

struct Sig
{
    G1 W;
    G1 V;
};

struct SK
{
    G1 D;
    Big x;
};


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

class XuCLAS{
public:

    XuCLAS(){
        pfc.random(P);  // generator of G1;
        q = pfc.order();  // order of G1
        pfc.random(s);   
        Pub = pfc.mult(P, s);
    }


    void reg(){         
        G1 Q;

        id = randbits(192); 
        char str[24] = {0};    
        to_binary(id, 24, str);
        pfc.hash_and_map(Q, str);
        sk.D = pfc.mult(Q, s);

        sk.x = rand(q);  // then we have SK={D,x}

        pk = pfc.mult(P, sk.x);
    }

    G1& getPK(){
        return pk;
    }

    Big& getID(){
        return id;
    }

    G1& getPub(){
        return Pub;
    }

    Sig& sign(string& m){        
        Big w = rand(q);
        sig.W = pfc.mult(P, w);

        st << id << pk.g << sig.W.g;
        Big alpha = Hash(st);
        st << m << id << pk.g << sig.W.g;
        Big beta = Hash(st);


        G1 Z;
        st << Pub.g;
        size_t size = st.tellp();
        char* buff = new char[size];
        st.read(buff, size);
        unsigned char value[HASH_LEN];
        pfc.hash_and_map(Z, buff);
        st.str("");
        delete[] buff;

        sig.V = pfc.mult(sk.D, alpha);
        Big tmp = w + beta * sk.x;
        sig.V = sig.V + pfc.mult(Z, tmp);

        return sig;
    }

private:
    G1 pk;
    Big q, id;
    SK sk;


    Sig sig;
    stringstream st;
};

bool verify(Sig& sig, Big& id, G1& pk, string& m){
        // suppose we have received PID, PK, T, m and s
        stringstream st;
        st << id << pk.g << sig.W.g;
        Big alpha = Hash(st);
        st << m << id << pk.g << sig.W.g;
        Big beta = Hash(st);


        G1 Z;
        st << Pub.g;
        size_t size = st.tellp();
        char* buff = new char[size];
        st.read(buff, size);
        unsigned char value[HASH_LEN];
        pfc.hash_and_map(Z, buff);
        st.str("");
        delete[] buff;

        G1 Q;
        char str[24] = {0};    
        to_binary(id, 24, str);
        pfc.hash_and_map(Q, str);

        GT left = pfc.pairing(sig.V, P);
        GT right = pfc.pairing(pfc.mult(Q, alpha), Pub);
        right = right * pfc.pairing(sig.W+pfc.mult(pk, beta), Z);

        if(left == right) {
            return true;
        }
            
        return false;
}

bool aggVerify(int n, string& msg, G1& aggSig, vector<Big>& vecID, vector<G1>& vecPK, vector<G1>& vecW){
    GT right;
    G1 r1, r2;
    stringstream st;
    GT left = pfc.pairing(aggSig, P);
    G1 Z;
    st << Pub.g;
    size_t size = st.tellp();
    char* buff = new char[size];
    st.read(buff, size);
    unsigned char value[HASH_LEN];
    pfc.hash_and_map(Z, buff);
    st.str("");
    delete[] buff;
    for(int i=0;i<n;i++){
        st << vecID[i] << vecPK[i].g << vecW[i].g;
        Big alpha = Hash(st);
        st << msg << vecID[i] << vecPK[i].g << vecW[i].g;
        Big beta = Hash(st);

        G1 Q;
        char str[24] = {0};    
        to_binary(vecID[i], 24, str);
        pfc.hash_and_map(Q, str);
        
        r1 = r1 + pfc.mult(Q, alpha);
        r2 = r2 + vecW[i] + pfc.mult(vecPK[i], beta);
    }
    right = pfc.pairing(r1, Pub) * pfc.pairing(r2, Z);
    if(left == right){
        return true;
    }
    return false;
}

void singleTest(XuCLAS& clas){
    long start;
    double diff;
    Sig sig;
    ECn left, right;
    string msg("This is a test.");
    cout << "First, we generate public key and scret key!" << endl;
    
    clas.reg();

    cout << "\nThen we compute the signature." << endl;
    start = clock();
    sig = clas.sign(msg);
    diff = ((double)clock() - start)/ CLOCKS_PER_SEC * 1000.0;
    cout << "Sig: {" << sig.V.g << ", " << sig.W.g << "}" << endl;
    printf("[*] Sign Time: %.6fms\n", diff);

    cout << "\nNow, we start to verify the sig." << endl;
    start = clock();
    if(verify(sig, clas.getID(), clas.getPK(), msg)){
        diff = ((double)clock() - start)/ CLOCKS_PER_SEC * 1000.0;
        printf("[*] ACCEPT! Verification Time: %.6fms\n", diff);
    }
}

void avgTest(XuCLAS& clas, int n){
    long s_start, v_start, s_total = 0, v_total = 0;
    Sig sig;
    ECn left, right;
    string msg("This is a test.");
    for(int i=0; i<n; i++){
        clas.reg();
        s_start = clock();
        sig = clas.sign(msg);
        s_total += clock() - s_start;
        v_start = clock();
        if(verify(sig, clas.getID(), clas.getPK(), msg)){
            v_total += clock() - v_start;
        }else{
            cout << "[x] verification reject!" << endl;
            exit(-1);
        }
    }
    printf("[*] Average Sign Time: %.6fms\n", (double)s_total / n / CLOCKS_PER_SEC * 1000.0);
    printf("[*] Average Verify Time: %.6fms\n", (double)v_total / n / CLOCKS_PER_SEC * 1000.0);
}

void aggTest(XuCLAS& ourclas, int n){
    string msg("This is a test.");
    vector<G1> vecW;
    vector<Big> vecID;
    vector<G1> vecPK;
    G1 aggSig;
    for(int i=0; i< n; i++){
        ourclas.reg();
        Sig sig = ourclas.sign(msg);
        aggSig = aggSig + sig.V;
        vecW.push_back(sig.W);
        vecID.push_back(ourclas.getID());
        vecPK.push_back(ourclas.getPK());
    }
    long start = clock();
    if(aggVerify(n, msg, aggSig, vecID, vecPK, vecW)){
        printf("[*] %d Aggregate Verify Time: %.6fms\n", n, ((double)clock() - start)/ CLOCKS_PER_SEC * 1000.0);
    }
}


int main(){
    irand(2022l); // 置随机种子
    cout << endl << "------------Xu-------------" << endl;
    XuCLAS ourclas;
    singleTest(ourclas);
    avgTest(ourclas, 100);
    aggTest(ourclas, 20);
    aggTest(ourclas, 40);
    aggTest(ourclas, 60);
    aggTest(ourclas, 80);
    aggTest(ourclas, 100);
    
    return 0;
}