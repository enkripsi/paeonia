#include "pk.h"

#include <botan/rsa.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/x509_key.h>

#include <iostream>

using namespace Botan;

class GenerateKeysWorker : public Nan::AsyncWorker {
  public:
    GenerateKeysWorker(
        Nan::Callback *callback,
        int keySize)
      : Nan::AsyncWorker(callback), keySize(keySize)
    {}

    ~GenerateKeysWorker() {}

    void Execute() {
      try {
        AutoSeeded_RNG rng;
        privateKey = std::unique_ptr<RSA_PrivateKey>(new RSA_PrivateKey(rng, keySize));
        publicKey = std::unique_ptr<RSA_PublicKey>(dynamic_cast<RSA_PublicKey *>(privateKey.get()));
      }
      catch (std::exception &e) {
        SetErrorMessage(e.what());
      }
    }

    void HandleOKCallback() {
      Nan::HandleScope scope;
      v8::Local<v8::Object> obj = Nan::New<v8::Object>();
      std::string privateKeyString = X509::PEM_encode(*privateKey.get());
      std::string publicKeyString = X509::PEM_encode(*publicKey.get());
      Nan::Set(obj, Nan::New("privateKey").ToLocalChecked(), 
        Nan::New((char *) privateKeyString.c_str(), 
          privateKeyString.size()).ToLocalChecked());
      Nan::Set(obj, Nan::New("publicKey").ToLocalChecked(), 
        Nan::New((char *) publicKeyString.c_str(), 
          publicKeyString.size()).ToLocalChecked());
      v8::Local<v8::Value> argv[] = {
        Nan::Null(),
        obj
      };
      callback->Call(2, argv);
    }
  
  private:
    int keySize;
    std::unique_ptr<RSA_PrivateKey> privateKey;
    std::unique_ptr<RSA_PublicKey> publicKey;
};

NAN_METHOD(GenerateKeys) {
  int keySize = info[0]->Uint32Value();
  Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());
  Nan::AsyncQueueWorker(new GenerateKeysWorker(callback, keySize));
}
