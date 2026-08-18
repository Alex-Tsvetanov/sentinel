// SipHash-2-4, the keyed pseudo-random function from Aumasson and Bernstein.
//
// Used for the stateless admission cookie and for the proof-of-work challenge.
// It is the right shape for both: keyed, fast on short messages, and designed
// so an attacker who sees outputs cannot produce a new valid one without the
// key. It is not a general-purpose signature primitive and is not used as one.
#pragma once

#include <cstddef>
#include <cstdint>

#include "sentinel/bytes.hpp"

namespace sentinel {

std::uint64_t siphash24(bytes_view msg, std::uint64_t k0, std::uint64_t k1);

// Same function over eight bytes of input, which is the only case the admission
// path needs and the one it runs on every packet.
std::uint64_t siphash24_u64(std::uint64_t msg, std::uint64_t k0, std::uint64_t k1);

}  // namespace sentinel
