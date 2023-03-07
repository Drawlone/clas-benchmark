#include <cstdio>
#include <ctime>

// g++ paper2-pairing.cpp ssp_pair.cpp zzn2.cpp ecn.cpp  miracl.a -o paper2-pairing.out

#define MR_PAIRING_SSP   
// #define MR_PAIRING_SS2	
// a super-singular curve over GF(p) implents Tate pairing
// p = B83DFB800C851836F9B95087F2642EF80B044116A536A5D5C35F02A297B82515F98C5E7D90AE1524653D8298402F5F35AE20D87A03E791E8DC6C070D564EC663

#define AES_SECURITY 80  // AES-80 security
#include "pairing_1.h"

int main(){
    PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
    
	G1 P, Q, S;
    GT R;
    Big s;
    char str[64] = {0};
    
    long end_pairing = 0, end_pair_mul = 0, end_pair_add = 0, 
    end_scalar_mul = 0, end_scalar_pow = 0, end_mtp = 0;
    for(int i=0; i<1000; i++){
        pfc.random(P);
        pfc.random(Q);
        GT T = pfc.pairing(P, Q);  // Just for generating GT

        // Pairing Test
        long start_pair = clock();
        R = pfc.pairing(P, Q);
        end_pairing += clock() - start_pair;

        // Pairing-based Mul Test GT
        long start_pair_mul = clock();
        R = R * T;
        end_pair_mul += clock() - start_pair_mul;

        // Pairing-based Add Test G1
        long start_pair_add = clock();
        S = P + Q;
        end_pair_add += clock() - start_pair_add;

        // Pairing-based scalar Mul on G1
        pfc.random(s);
        long start_scalar_mul = clock();
        S = pfc.mult(P, s);
        end_scalar_mul += clock() - start_scalar_mul;

        // Pairing-based scalar Pow on GT
        long start_scalar_pow = clock();
        R = pfc.power(T, s);
        end_scalar_pow += clock() - start_scalar_pow;

        // map-to-point test
        Big k = randbits(192);     
        to_binary(k, 64, str);
        long start_mtp = clock();
        pfc.hash_and_map(S, str);
        end_mtp += clock() - start_mtp;
    }
    double pairAvgTime =  end_pairing / 1000.0 / CLOCKS_PER_SEC * 1000.0;
    double mulAvgTime =  end_pair_mul / 1000.0 / CLOCKS_PER_SEC * 1000.0;
    double addAvgTime =  end_pair_add / 1000.0 / CLOCKS_PER_SEC * 1000.0;
    double scalarMulAvgTime =  end_scalar_mul / 1000.0 / CLOCKS_PER_SEC * 1000.0;
    double scalarPowAvgTime =  end_scalar_pow / 1000.0 / CLOCKS_PER_SEC * 1000.0;
    double mtpAvgTime =  end_mtp / 1000.0 / CLOCKS_PER_SEC * 1000.0;
    printf("[*] Pairing Opertion Time: %.6fms\n", pairAvgTime);
    printf("[*] Pairing Multiplication Opertion Time: %.6fms\n", mulAvgTime);
    printf("[*] Pairing Addition Opertion Time: %.6fms\n", addAvgTime);
    printf("[*] Pairing Scalar Multiplication Opertion On G1 Time: %.6fms\n", scalarMulAvgTime);
    printf("[*] Pairing Scalar Power On GT Opertion Time: %.6fms\n", scalarPowAvgTime);
    printf("[*] Map To Point Opertion Time: %.6fms\n", mtpAvgTime);




    

    return 0;
}

