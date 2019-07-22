/**
 * @file	message_digest.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "message_digest.hpp"
#include "provider.hpp"
#include "security.hpp"

namespace jcp {

	std::unique_ptr<MessageDigest> MessageDigest::getInstance(const char* name, std::shared_ptr<Provider> provider)
	{
		MessageDigestFactory* factory = provider ? provider->getMessageDigest(name) : Security::findMessageDigest(name);
		if (factory)
			return std::move(factory->create());
		return NULL;
	}

	std::unique_ptr<MessageDigest> MessageDigest::getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider)
	{
		MessageDigestFactory* factory = provider ? provider->getMessageDigest(algo_id) : Security::findMessageDigest(algo_id);
		if (factory)
			return std::move(factory->create());
		return NULL;
	}

}
