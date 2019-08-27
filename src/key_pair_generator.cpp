#include <jcp/key_pair_generator.hpp>

#include <jcp/security.hpp>

namespace jcp {

    std::unique_ptr<KeyPairGenerator> KeyPairGenerator::getInstance(const char* name, std::shared_ptr<Provider> provider)
    {
        KeyPairGeneratorFactory *factory = provider ? provider->getKeyPairGenerator(name) : Security::findKeyPairGenerator(name);
        if(factory)
            return std::move(factory->create());
        return NULL;
    }

    std::unique_ptr<KeyPairGenerator> KeyPairGenerator::getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider)
    {
        KeyPairGeneratorFactory *factory = provider ? provider->getKeyPairGenerator(algo_id) : Security::findKeyPairGenerator(algo_id);
        if(factory)
            return std::move(factory->create());
        return NULL;
    }

}

