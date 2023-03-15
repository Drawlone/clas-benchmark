#include <iostream>
#include <sstream>
#include "include/clas.h"
#include <string>
#include <vector>

struct PID
{
    ECn pid1;
    Big pid2;
};

class OurCLAS: public Clas{
public:
    virtual void reg(){      
        sk.x = rand(q);       
        Big r = rand(q);
        pk.X = sk.x * g, pk.R = r * g;
        pid = PID{rand(q)*g, randbits(256)};
        // cout << "PK: {" << pk.X << ", " << pk.R << "}" << endl;
        st << pid.pid1 << pid.pid2 << pk.R << Pub;
        // h1_struct = H1{pid, pk.R, Pub};        
        Big h1 = Hash(st);
        sk.d = r + alpha * h1;
        // cout << "sk: {" << sk.x << ", " << sk.d << "}" << endl;

    }

    PK& getPK(){
        return pk;
    }

    PID& getPID(){
        return pid;
    }

    long getTimestamp(){
        return t;
    }

    ECn& getPub(){
        return Pub;
    }

    virtual Sig& sign(string& m){        
        Big u = rand(q);
        ECn U = u * g;
        t = clock();
        // h2_struct = H2{pid, pk, U, t};
        // h3_struct = H3{pid, U};
        st << pid.pid1 << pid.pid2 << m << pk.X << pk.R << U << t;
        Big h2 = Hash(st);
        st << pid.pid1 << pid.pid2 << m << U;
        Big h3 = Hash(st);

        sig.s = u + sk.x * h3 + sk.d * h2;
        sig.U = U;
        return sig;
    }

private:
    PK pk;
    SK sk;
    Sig sig;
    stringstream st;
    long t;
    PID pid;

    // struct H1
    // {
    //     PID pid;
    //     ECn R;
    //     ECn Pub;
    // } h1_struct;  

    // struct H2
    // {
    //     PID pid;
    //     PK pk;
    //     ECn U;
    //     long T;
    // } h2_struct;

    // struct H3
    // {
    //     PID pid;
    //     ECn U;
    // } h3_struct;

};

bool verify(Sig& sig, PID& pid, PK& pk, ECn& Pub, string& m, long timestp){
        // suppose we have received PID, PK, T, m and s
        long start = clock();
        stringstream st;
        ECn left, right;
        st << pid.pid1 << pid.pid2 << pk.R << Pub;
        Big h1 = Hash(st);
        st << pid.pid1 << pid.pid2 << m << pk.X << pk.R << sig.U << timestp;
        Big h2 = Hash(st);
        st << pid.pid1 << pid.pid2 << m << sig.U;
        Big h3 = Hash(st);
        left = sig.s * g;
        right = h1 * Pub;
        right += pk.R;
        right *= h2;
        right += h3 * pk.X;
        right += sig.U;
        // cout << left << endl << right << endl;
        if(left == right) {
            return true;
        }
            
        return false;
}

bool aggVerify(int n, string& msg, Big& aggSig, vector<PID>& vecPID, vector<PK>& vecPK, vector<ECn>& vecU, vector<long>& vecT){
long start = clock();
    ECn right, r1, r2;
    Big r3;
    stringstream st;
    ECn left = aggSig * g;
    for(int i=0;i<n;i++){
        st << vecPID[i].pid1 << vecPID[i].pid2 << vecPK[i].R << Pub;
        Big h1 = Hash(st);
        st << vecPID[i].pid1 <<vecPID[i].pid2 << msg << vecPK[i].X << vecPK[i].R << vecU[i] << vecT[i];
        Big h2 = Hash(st);
        st << vecPID[i].pid1 << vecPID[i].pid2 << msg << vecU[i];
        Big h3 = Hash(st);

        r1 += vecU[i];
        r2 += h3 * vecPK[i].X;
        r2 += h2 * vecPK[i].R;
        r3 += h1 * h2;
    }
    right += r1;
    right += r2;
    right += r3 * Pub;
    if(left == right){
        return true;
    }
    return false;
}

void singleTest(OurCLAS& clas){
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
    cout << "Sig: {" << sig.U << ", " << sig.s << "}" << endl;
    printf("[*] Sign Time: %.6fms\n", diff);

    cout << "\nNow, we start to verify the sig." << endl;
    start = clock();
    if(verify(sig, clas.getPID(), clas.getPK(), clas.getPub(), msg, clas.getTimestamp())){
        diff = ((double)clock() - start)/ CLOCKS_PER_SEC * 1000.0;
        printf("[*] ACCEPT! Verification Time: %.6fms\n", diff);
    }
}

void avgTest(OurCLAS& clas, int n){
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
        if(verify(sig, clas.getPID(), clas.getPK(), clas.getPub(), msg, clas.getTimestamp())){
            v_total += clock() - v_start;
        }else{
            cout << "[x] verification reject!" << endl;
            exit(-1);
        }
    }
    printf("[*] Average Sign Time: %.6fms\n", (double)s_total / n / CLOCKS_PER_SEC * 1000.0);
    printf("[*] Average Verify Time: %.6fms\n", (double)v_total / n / CLOCKS_PER_SEC * 1000.0);
}

void aggTest(OurCLAS& ourclas, int n){
    string msg("This is a test.");
    vector<ECn> vecU;
    vector<PID> vecPID;
    vector<PK> vecPK;
    vector<long> vecT;
    Big aggSig(0);
    for(int i=0; i< n; i++){
        ourclas.reg();
        Sig sig = ourclas.sign(msg);
        aggSig += sig.s;
        vecU.push_back(sig.U);
        vecPID.push_back(ourclas.getPID());
        vecPK.push_back(ourclas.getPK());
        vecT.push_back(ourclas.getTimestamp());
    }
    long start = clock();
    if(aggVerify(n, msg, aggSig, vecPID, vecPK, vecU, vecT)){
        printf("[*] %d Aggregate Verify Time: %.6fms\n", n, ((double)clock() - start)/ CLOCKS_PER_SEC * 1000.0);
    }
}


int main(){
    irand(2022l); // 置随机种子
    setup();
    cout << endl << "------------Our-------------" << endl;
    OurCLAS ourclas;
    // singleTest(ourclas);
    avgTest(ourclas, 100);
    aggTest(ourclas, 20);
    aggTest(ourclas, 40);
    aggTest(ourclas, 60);
    aggTest(ourclas, 80);
    aggTest(ourclas, 100);
    
    return 0;
}