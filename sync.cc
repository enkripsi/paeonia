#include "sync.h"
#include <botan/rsa.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/x509_key.h>

using namespace Botan;

NAN_METHOD(GenerateKeysSync) {
  int keySize = info[0]->Uint32Value();
  
  AutoSeeded_RNG rng;
  auto *privateKey = new RSA_PrivateKey(rng, keySize);
  auto *publicKey = dynamic_cast<RSA_PublicKey *>(privateKey);

  std::string privateKeyString = X509::PEM_encode(*privateKey);
  std::string publicKeyString = X509::PEM_encode(*publicKey);

  v8::Local<v8::Object> obj = Nan::New<v8::Object>();
  Nan::Set(obj, Nan::New("privateKey").ToLocalChecked(), 
      Nan::New((char *) privateKeyString.c_str(), 
        privateKeyString.size()).ToLocalChecked());
  Nan::Set(obj, Nan::New("publicKey").ToLocalChecked(), 
      Nan::New((char *) publicKeyString.c_str(), 
        publicKeyString.size()).ToLocalChecked());
  info.GetReturnValue().Set(obj);
}


