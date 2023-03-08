#ifndef CLAS_H
#define CLAS_H
#include "miracl.h"
#include "big.h"
#include "ecn.h"
#include <openssl/sha.h>

extern Miracl precision;
extern ECn g, Pub;
extern Big q, alpha;


#define HASH_LEN 32

struct Sig
{
    ECn U;
    Big s;
};

struct PK{
    ECn X;
    ECn R;
};

struct SK{
    Big x;
    Big d;
};
void setup();
Big Hash(stringstream &st);

class Clas{
private:
public:
    virtual void reg() = 0;
    virtual Sig& sign(string& m) = 0;
    virtual PK& getPK() = 0;
    virtual ECn& getPub() = 0;
};

#endif