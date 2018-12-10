#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/pem.h>
#include <string>

using namespace CryptoPP;
using namespace std;

int main(){
    
    string pub,priv;
    
    AutoSeededRandomPool rng;
    RSA::PrivateKey privkey;
    privkey.GenerateRandomWithKeySize(rng, 1024);
    RSA::PublicKey pubkey(privkey);
    
    FileSink fs16("rsa-pub-xxx.txt", true);
    //Base64Encoder pubkeysink(new StringSink(pub));
    PEM_Save(fs16, pubkey);
    StringSink ss2(pub);
    PEM_Save(ss2.Ref(), pubkey);
    
    // Save an encrypted EC private key
    AutoSeededRandomPool prng;
    //DL_PrivateKey_EC<ECP> k18 = ...;
    FileSink fs18("rsa-priv-xxx.pem", true);
    //Base64Encoder privkeysink(new StringSink(priv));
    PEM_Save(fs18, privkey);
    StringSink ss(priv);
    PEM_Save(ss.Ref(), privkey);
    
    cout << "Private Key" << endl;
    cout << priv << endl;
    cout << "Public Key" << endl;
    cout << pub << endl;
}