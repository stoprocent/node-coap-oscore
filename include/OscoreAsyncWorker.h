#ifndef OSCORE_ASYNC_WORKER_H
#define OSCORE_ASYNC_WORKER_H

#include <napi.h>
#include <vector>

extern "C" {
#include "oscore.h"
}

class OscoreAsyncWorker : public Napi::AsyncWorker {
 public:
  using CallbackType = std::function<void(Napi::Env&)>;

  enum Direction {
    Encode,
    Decode
  };

  OscoreAsyncWorker(Napi::Env& env,
                    struct context& context,
                    Direction direction,
                    Napi::Buffer<uint8_t> buffer,
                    CallbackType callback);

  /**
   * @brief Executes the asynchronous worker task.
   */
  void Execute() override;

  /**
   * @brief Executes when the asynchronous worker task is completed
   * successfully.
   */
  void OnOK() override;

  /**
   * @brief Executes when an error occurs during the asynchronous worker task.
   * @param error The Napi::Error object.
   */
  void OnError(const Napi::Error& error) override;

  /**
   * @brief Returns the promise of the asynchronous worker.
   * @return The promise of the asynchronous worker.
   */
  Napi::Promise Promise();

 private:
  Napi::Promise::Deferred deferred;
  struct context& context;
  Direction direction;
  std::vector<uint8_t> inputBuffer;
  std::vector<uint8_t> outputBuffer;
  CallbackType callback;
};

#endif  // OSCORE_ASYNC_WORKER_H