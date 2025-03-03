#include <iostream>
#include <thread>
#include <cstdint>
#include <future>
#include <exception>
#include <stdexcept>
#include <napi.h>

#include "OscoreAsyncWorker.h"
#include "SecurityContextRegistry.h"

extern "C" {
  #include "oscore.h"
  #include "crypto_wrapper.h"
}

static constexpr const char* kClassNameOSCORE = "OSCORE";

class OSCORE : public Napi::ObjectWrap<OSCORE> {
  public:
        
    uint64_t senderSequenceNumber;
    
    enum ContextStatus {
      Fresh = 0,
      Restored = 1,
    };

    OSCORE(const Napi::CallbackInfo& info) : Napi::ObjectWrap<OSCORE>(info) {
      Napi::Env env = info.Env();
      Napi::HandleScope scope(env);

      // Get secure context
      this->secureContext = Napi::Persistent(info[0].As<Napi::Object>());
            
      Napi::Buffer<uint8_t> masterSecret = this->secureContext.Get("masterSecret").As<Napi::Buffer<uint8_t>>();
      Napi::Buffer<uint8_t> senderId = this->secureContext.Get("senderId").As<Napi::Buffer<uint8_t>>();
      Napi::Buffer<uint8_t> recipientId = this->secureContext.Get("recipientId").As<Napi::Buffer<uint8_t>>();
      Napi::Buffer<uint8_t> idContext = this->secureContext.Get("idContext").As<Napi::Buffer<uint8_t>>();
      Napi::Buffer<uint8_t> masterSalt = this->secureContext.Get("masterSalt").As<Napi::Buffer<uint8_t>>();
      
      // Check if ssn exists in secureContext, if not default to 0
      if (this->secureContext.Value().As<Napi::Object>().Has("ssn")) {
        bool lossless;
        this->senderSequenceNumber = this->secureContext.Get("ssn").As<Napi::BigInt>().Uint64Value(&lossless);
        if (!lossless) {
          Napi::TypeError::New(env, "Sender sequence number is not a valid uint64_t")
            .ThrowAsJavaScriptException();
          return;
        }
      } else {
        this->senderSequenceNumber = 0;
      }

      // Get context status
      ContextStatus contextStatus = ContextStatus::Fresh;
      if (this->secureContext.Value().As<Napi::Object>().Has("status")) {
        uint32_t jsContextStatus = this->secureContext.Get("status").As<Napi::Number>().Uint32Value();
        contextStatus = static_cast<ContextStatus>(jsContextStatus);
      }

      // Initialize OSCORE parameters
      struct oscore_init_params oscore_params = {
        { static_cast<uint32_t>(masterSecret.Length()), (uint8_t *)masterSecret.Data() },
        { static_cast<uint32_t>(senderId.Length()), (uint8_t *)senderId.Data() },
        { static_cast<uint32_t>(recipientId.Length()), (uint8_t *)recipientId.Data() },
        { static_cast<uint32_t>(idContext.Length()), (uint8_t *)idContext.Data() },
        { static_cast<uint32_t>(masterSalt.Length()), (uint8_t *)masterSalt.Data() },
        OSCORE_AES_CCM_16_64_128,
        OSCORE_SHA_256,
        (contextStatus == ContextStatus::Fresh)
      };

      // Register in SecurityContextRegistry
      struct nvm_key_t nvm_key = { 
        .sender_id = oscore_params.sender_id,
        .recipient_id = oscore_params.recipient_id,
        .id_context = oscore_params.id_context 
      };
      SecurityContextRegistry::getInstance()->registerContext(&nvm_key, this);

      // Initialize OSCORE context
      this->context = {};
      err status = oscore_context_init(&oscore_params, &this->context);

      if (status != ok) {
        Napi::TypeError::New(env, "Could not initialize OSCORE Context, status=" + std::to_string((int)status) )
            .ThrowAsJavaScriptException();
        return;
      }
    }

    ~OSCORE() {
      this->context = {};
    }

    Napi::Value encode(const Napi::CallbackInfo& info) {
      return this->convert(info, OscoreAsyncWorker::Direction::Encode);
    }

    Napi::Value decode(const Napi::CallbackInfo& info) {
      return this->convert(info, OscoreAsyncWorker::Direction::Decode);
    }

    Napi::Value convert(const Napi::CallbackInfo& info, OscoreAsyncWorker::Direction direction) {
      Napi::Env env = info.Env();
      Napi::HandleScope scope(env);

      self = Napi::ObjectReference::New(info.This().As<Napi::Object>());

      if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Expected first argument to be a buffer")
          .ThrowAsJavaScriptException();
        return env.Null();
      }

      Napi::Buffer<uint8_t> inputBuffer = info[0].As<Napi::Buffer<uint8_t>>();
      
      OscoreAsyncWorker::CallbackType callback = [this](Napi::Env& env) {
        Napi::Function emit = this->self.Value().As<Napi::Object>().Get("emit").As<Napi::Function>();
        emit.Call(this->self.Value(), { Napi::String::New(env, "ssn"), Napi::BigInt::New(env, this->senderSequenceNumber) });
      };

      OscoreAsyncWorker* worker = new OscoreAsyncWorker(env, context, direction, inputBuffer, callback);
      worker->Queue();

      return worker->Promise();
    }

    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
      Napi::HandleScope scope(env);
      Napi::Function func = DefineClass(
        env, kClassNameOSCORE,
        {
            InstanceMethod("encode", &OSCORE::encode),
            InstanceMethod("decode", &OSCORE::decode)
        });

      Napi::FunctionReference* constructor = new Napi::FunctionReference();
      *constructor = Napi::Persistent(func);
      env.SetInstanceData(constructor);

      exports.Set(kClassNameOSCORE, func);
      return exports;
    }

  private:
    struct context context;
    Napi::ObjectReference self;
    Napi::ObjectReference secureContext;

};

extern "C" enum err nvm_write_ssn(const struct nvm_key_t *nvm_key, uint64_t ssn) {
  void* ptr = SecurityContextRegistry::getInstance()->getContext(nvm_key);
  if (ptr) {
    OSCORE* oscore = static_cast<OSCORE*>(ptr);
    oscore->senderSequenceNumber = ssn;
    return ok;
  }
  return unexpected_result_from_ext_lib;
}

extern "C" enum err nvm_read_ssn(const struct nvm_key_t *nvm_key, uint64_t *ssn)
{
  void* ptr = SecurityContextRegistry::getInstance()->getContext(nvm_key);
  if (ptr) {
    *ssn = static_cast<OSCORE*>(ptr)->senderSequenceNumber;
    return ok;
  }
  return unexpected_result_from_ext_lib;
}

NODE_API_NAMED_ADDON(addon, OSCORE);
