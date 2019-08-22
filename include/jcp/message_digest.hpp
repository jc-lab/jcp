/**
 * @file	message_digest.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_MESSAGE_DIGEST_H__
#define __JCP_MESSAGE_DIGEST_H__

#include <memory>
#include <vector>

#include "buffer.hpp"
#include "result.hpp"

namespace jcp {

    class Provider;
    class MessageDigest {
    protected:
        Provider *provider_;

    public:
        static std::unique_ptr<MessageDigest> getInstance(const char *name, std::shared_ptr<Provider> provider = NULL);
        static std::unique_ptr<MessageDigest> getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider = NULL);

        MessageDigest(Provider *provider) : provider_(provider) {}
        Provider *getProvider() const { return provider_; }

        virtual int digest_size() = 0;
        virtual jcp::Result<void> update(const void *buf, size_t length) = 0;
        virtual jcp::Result<void> digest(unsigned char *buf) = 0;
        virtual jcp::Result<Buffer> digest() = 0;

		jcp::Result<void> update(unsigned char data) {
			return update(&data, 1);
		}
    };

    class MessageDigestFactory {
    protected:
        Provider *provider_;

    public:
        MessageDigestFactory(Provider *provider) : provider_(provider) {}

        virtual std::unique_ptr<MessageDigest> create() = 0;
    };

}

#endif // __JCP_MESSAGE_DIGEST_H__
