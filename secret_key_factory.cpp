#include "secret_key_factory.hpp"

#include "security.hpp"

namespace jcp {

	const SecretKeyFactory* SecretKeyFactory::getInstance(const char* name, std::shared_ptr<Provider> provider)
	{
		return provider ? provider->getSecretKeyFactory(name) : Security::findSecretKeyFactory(name);
	}

	const SecretKeyFactory* SecretKeyFactory::getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider)
	{
		return provider ? provider->getSecretKeyFactory(algo_id) : Security::findSecretKeyFactory(algo_id);
	}

}

