/**
 * @file	mac.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_MAC_H__
#define __JCP_MAC_H__

#include <memory>
#include "result.hpp"
#include "secret_key.hpp"

namespace jcp {

	class Provider;
    class Mac {
    protected:
        Provider *provider_;

    public:
        static std::unique_ptr<Mac> getInstance(const char *name, std::shared_ptr<Provider> provider = NULL);
        static std::unique_ptr<Mac> getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider = NULL);

        Mac(Provider *provider) : provider_(provider) {}
        Provider *getProvider() const { return provider_; }

		virtual jcp::Result<void> init(SecretKey* key) = 0;
        virtual int digest_size() const = 0;
        virtual jcp::Result<void> update(const void *buf, size_t length) = 0;
        virtual jcp::Result<void> digest(unsigned char *buf) = 0;
        virtual jcp::Result<Buffer> digest() = 0;

        virtual void reset() = 0;

        int getMacLength() const {
            return digest_size();
        }

        virtual jcp::Result<Buffer> doFinal() {
            jcp::Result<Buffer> result = digest();
            reset();
            return std::move(result);
        }
    };

    class MacFactory {
    protected:
        Provider *provider_;

    public:
        MacFactory(Provider *provider) : provider_(provider) {}

        virtual std::unique_ptr<Mac> create() = 0;
    };

}

#endif // __JCP_MAC_H__
