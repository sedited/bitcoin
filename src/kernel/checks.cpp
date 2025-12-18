// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/checks.h>

#include <random.h>
#include <util/expected.h>

#include <string>

namespace kernel {

util::Expected<void, std::string> SanityChecks(const Context&)
{
    if (!Random_SanityCheck()) {
        return util::Unexpected{"OS cryptographic RNG sanity check failure. Aborting."};
    }

    return {};
}

}
