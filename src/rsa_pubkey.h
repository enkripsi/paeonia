#ifndef PAEONIA_PUBKEY_H
#define PAEONIA_PUBKEY_H

#include <nan.h>
#include <botan/x931_rng.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>

namespace paeonia {

class GenerateKeyPairWorker;

class RSAPubKey : public Nan::ObjectWrap {
  
  friend class GenerateKeyPairWorker;

  public:
    static void Init(v8::Local<v8::Object> exports);

  private:
    explicit RSAPubKey(size_t keyLength);
    ~RSAPubKey();

    static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void GenerateKeyPair(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Encode(const Nan::FunctionCallbackInfo<v8::Value>& info);
    
    static Nan::Persistent<v8::Function> constructor;

  private:
    size_t keySize;
    Botan::RSA_PrivateKey* key;
    Botan::ANSI_X931_RNG* rng;
};

};

#endif
