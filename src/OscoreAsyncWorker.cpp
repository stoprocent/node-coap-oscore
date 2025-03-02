#include <thread>
#include <chrono>

#include "OscoreAsyncWorker.h"
#include "OscoreError.h"

OscoreAsyncWorker::OscoreAsyncWorker(Napi::Env& env,
                                     struct context& context,
                                     Direction direction,
                                     Napi::Buffer<uint8_t> buffer,
                                     CallbackType callback)
    : Napi::AsyncWorker(env),
      deferred(Napi::Promise::Deferred::New(env)),
      context(context),
      direction(direction),
      inputBuffer(buffer.Data(), buffer.Data() + buffer.Length()),
      outputBuffer(10240),
      callback(std::move(callback)) {}

void OscoreAsyncWorker::Execute() {
  try {
    std::this_thread::sleep_for(std::chrono::seconds(2));

    uint32_t outputBufferLength = 0;
    err status;

    if (direction == Direction::Encode) {
      if ((status = coap2oscore((uint8_t *)inputBuffer.data(), inputBuffer.size(), outputBuffer.data(), &outputBufferLength, &context)) != ok) {
        throw OscoreError(status);
      }
    } 
    else if (direction == Direction::Decode) {
      if ((status = oscore2coap(inputBuffer.data(), inputBuffer.size(), outputBuffer.data(), &outputBufferLength, &context)) != ok) {
        throw OscoreError(status);
      }
    } else {
      throw std::runtime_error("Invalid direction");
    }

    outputBuffer.resize(outputBufferLength);

  } catch (const OscoreError& e) {
    SetError(e.what());
  }
}

void OscoreAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  deferred.Resolve(Napi::Buffer<uint8_t>::Copy(env, outputBuffer.data(), outputBuffer.size()));
  callback(env);
}

void OscoreAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  deferred.Reject(error.Value());
  callback(env);
}

Napi::Promise OscoreAsyncWorker::Promise() {
  return deferred.Promise();
}
