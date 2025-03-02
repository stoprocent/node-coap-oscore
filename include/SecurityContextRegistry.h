// SecurityContextRegistry.h
#ifndef SECURITY_CONTEXT_REGISTRY_H
#define SECURITY_CONTEXT_REGISTRY_H

#include <map>
#include <string>

// Forward declaration of your structures
struct byte_array;
struct nvm_key_t;

class SecurityContextRegistry {
private:
    // Map to store generic context pointers with string keys
    std::map<std::string, void*> contextMap;
    
    // Convert nvm_key_t to string key
    std::string createKeyString(const struct nvm_key_t* key);
    
    // Singleton instance
    static SecurityContextRegistry* instance;
    
    // Private constructor for singleton
    SecurityContextRegistry() {}
    
public:
    // Get singleton instance
    static SecurityContextRegistry* getInstance();
    
    // Register any context pointer
    void registerContext(const struct nvm_key_t* key, void* context);
    
    // Get a context pointer
    void* getContext(const struct nvm_key_t* key);
    
    // Unregister a context
    void unregisterContext(const struct nvm_key_t* key);
    
    // Clear all contexts
    void clearAll();
    
    // Destructor
    ~SecurityContextRegistry();
};

#endif // SECURITY_CONTEXT_REGISTRY_H