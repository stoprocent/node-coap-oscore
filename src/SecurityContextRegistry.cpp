#include "SecurityContextRegistry.h"

extern "C" {
  #include "oscore.h"
  #include "crypto_wrapper.h"
}

// Initialize the static instance
SecurityContextRegistry* SecurityContextRegistry::instance = nullptr;

std::string SecurityContextRegistry::createKeyString(const struct nvm_key_t* key) {
    std::string result;
    
    // Add sender_id bytes
    result.append(reinterpret_cast<const char*>(key->sender_id.ptr), key->sender_id.len);
    result.push_back('|');
    
    // Add recipient_id bytes
    result.append(reinterpret_cast<const char*>(key->recipient_id.ptr), key->recipient_id.len);
    result.push_back('|');
    
    // Add id_context bytes
    result.append(reinterpret_cast<const char*>(key->id_context.ptr), key->id_context.len);
    
    return result;
}

SecurityContextRegistry* SecurityContextRegistry::getInstance() {
    if (instance == nullptr) {
        instance = new SecurityContextRegistry();
    }
    return instance;
}

void SecurityContextRegistry::registerContext(const nvm_key_t* key, void* context) {
    std::string keyStr = createKeyString(key);
    contextMap[keyStr] = context;
}

void* SecurityContextRegistry::getContext(const nvm_key_t* key) {
    std::string keyStr = createKeyString(key);
    auto it = contextMap.find(keyStr);
    if (it != contextMap.end()) {
        return it->second;
    }
    return nullptr;
}

void SecurityContextRegistry::unregisterContext(const nvm_key_t* key) {
    std::string keyStr = createKeyString(key);
    contextMap.erase(keyStr);
}

void SecurityContextRegistry::clearAll() {
    contextMap.clear();
}

SecurityContextRegistry::~SecurityContextRegistry() {
    contextMap.clear();
}