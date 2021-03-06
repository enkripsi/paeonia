#ifndef PAEONIA_PUBKEY_H
#define PAEONIA_PUBKEY_H

#include <nan.h>
#include <botan/auto_rng.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>

namespace paeonia {

class GenerateKeyPairWorker;

class RSAPubKey : public Nan::ObjectWrap {
  
  friend class GenerateKeyPairWorker;
  friend class LoadKeyWorker;

  public:
    static void Init(v8::Local<v8::Object> exports);

  private:
    explicit RSAPubKey(size_t keyLength);
    ~RSAPubKey();

    static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void GenerateKeyPair(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Encode(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void LoadPublicKey(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void LoadPrivateKey(const Nan::FunctionCallbackInfo<v8::Value>& info);
    static void Encrypt(const Nan::FunctionCallbackInfo<v8::Value>& info);

    static void GetEncodedPublicKey(const Nan::FunctionCallbackInfo<v8::Value>& info, const RSAPubKey* obj, const std::string& encoding = "PEM");
    
    static Nan::Persistent<v8::Function> constructor;

  private:
    size_t keySize;
    Botan::RSA_PublicKey* publicKey;
    Botan::RSA_PrivateKey* privateKey;
    Botan::RandomNumberGenerator* rng;
};

};

#endif
