/**
 * @file	signature_algo.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/signature_algo.hpp>

namespace jcp {

    int SignatureAlgorithm::static_ordinal_ = 0;

    const SignatureAlgorithm SignatureAlgorithm::NONEwithECDSA(0x052100CD, "NONEwithECDSA");
    const SignatureAlgorithm SignatureAlgorithm::SHA1withECDSA(0x052111F1, "SHA1withECDSA");
    const SignatureAlgorithm SignatureAlgorithm::SHA224withECDSA(0x052112B0, "SHA224withECDSA");
    const SignatureAlgorithm SignatureAlgorithm::SHA256withECDSA(0x052113D1, "SHA256withECDSA");
    const SignatureAlgorithm SignatureAlgorithm::SHA384withECDSA(0x052114C3, "SHA384withECDSA");
    const SignatureAlgorithm SignatureAlgorithm::SHA512withECDSA(0x052115BA, "SHA512withECDSA");
	const SignatureAlgorithm SignatureAlgorithm::NONEwithRSA(0x051100C3, "NONEwithRSA");
	const SignatureAlgorithm SignatureAlgorithm::SHA1withRSA(0x051111D2, "SHA1withRSA");
	const SignatureAlgorithm SignatureAlgorithm::SHA224withRSA(0x051112A1, "SHA224withRSA");
	const SignatureAlgorithm SignatureAlgorithm::SHA256withRSA(0x0511139B, "SHA256withRSA");
	const SignatureAlgorithm SignatureAlgorithm::SHA384withRSA(0x051114C2, "SHA384withRSA");
	const SignatureAlgorithm SignatureAlgorithm::SHA512withRSA(0x051115AA, "SHA512withRSA");

    SignatureAlgorithm::SignatureAlgorithm(uint32_t algo_id, const char *name)
        : ordinal_(++static_ordinal_), algo_id_(algo_id), name_(name) {
    }

    SignatureAlgorithm::StaticInitializer::StaticInitializer() {
		list_.push_back(&NONEwithECDSA);
		list_.push_back(&SHA1withECDSA);
		list_.push_back(&SHA224withECDSA);
		list_.push_back(&SHA256withECDSA);
		list_.push_back(&SHA384withECDSA);
		list_.push_back(&SHA512withECDSA);
		list_.push_back(&NONEwithRSA);
		list_.push_back(&SHA1withRSA);
		list_.push_back(&SHA224withRSA);
		list_.push_back(&SHA256withRSA);
		list_.push_back(&SHA384withRSA);
		list_.push_back(&SHA512withRSA);
    }

}
