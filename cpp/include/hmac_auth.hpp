/**
 * ================================================================
 * Rex IoT Security Framework — C++ Core
 * Rex Cybersecurity Project
 * ================================================================
 * File: hmac_auth.hpp
 * Description: HMAC-SHA256 packet authentication for IoT devices.
 *              Implements RFC 2104 HMAC using a software SHA-256.
 *              Suitable for resource-constrained IoT gateways.
 * ================================================================
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <array>
#include <string>
#include <vector>

namespace Rex {
namespace Crypto {

// ── Software SHA-256 Implementation ──────────────────────────
class SHA256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;
    static constexpr size_t BLOCK_SIZE  = 64;

    SHA256() { reset(); }

    void reset() {
        state_[0] = 0x6a09e667UL; state_[1] = 0xbb67ae85UL;
        state_[2] = 0x3c6ef372UL; state_[3] = 0xa54ff53aUL;
        state_[4] = 0x510e527fUL; state_[5] = 0x9b05688cUL;
        state_[6] = 0x1f83d9abUL; state_[7] = 0x5be0cd19UL;
        bit_count_ = 0;
        buffer_len_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer_[buffer_len_++] = data[i];
            if (buffer_len_ == BLOCK_SIZE) {
                process_block();
                buffer_len_ = 0;
                bit_count_ += 512;
            }
        }
    }

    void finalize(uint8_t digest[DIGEST_SIZE]) {
        bit_count_ += buffer_len_ * 8;
        buffer_[buffer_len_++] = 0x80;
        if (buffer_len_ > 56) {
            while (buffer_len_ < BLOCK_SIZE) buffer_[buffer_len_++] = 0;
            process_block();
            buffer_len_ = 0;
        }
        while (buffer_len_ < 56) buffer_[buffer_len_++] = 0;
        for (int i = 7; i >= 0; --i)
            buffer_[buffer_len_++] = static_cast<uint8_t>(bit_count_ >> (i * 8));
        process_block();
        for (int i = 0; i < 8; ++i)
            for (int j = 3; j >= 0; --j)
                digest[i * 4 + (3 - j)] = static_cast<uint8_t>(state_[i] >> (j * 8));
    }

    static void hash(const uint8_t* data, size_t len, uint8_t digest[DIGEST_SIZE]) {
        SHA256 h; h.update(data, len); h.finalize(digest);
    }

private:
    static constexpr uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    };

    inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    inline uint32_t ch(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
    inline uint32_t maj(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
    inline uint32_t sigma0(uint32_t x) { return rotr(x,2)^rotr(x,13)^rotr(x,22); }
    inline uint32_t sigma1(uint32_t x) { return rotr(x,6)^rotr(x,11)^rotr(x,25); }
    inline uint32_t gamma0(uint32_t x) { return rotr(x,7)^rotr(x,18)^(x>>3); }
    inline uint32_t gamma1(uint32_t x) { return rotr(x,17)^rotr(x,19)^(x>>10); }

    void process_block() {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (buffer_[i*4]<<24)|(buffer_[i*4+1]<<16)|(buffer_[i*4+2]<<8)|buffer_[i*4+3];
        for (int i = 16; i < 64; ++i)
            w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
        uint32_t a=state_[0],b=state_[1],c=state_[2],d=state_[3];
        uint32_t e=state_[4],f=state_[5],g=state_[6],h=state_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sigma1(e) + ch(e,f,g) + K[i] + w[i];
            uint32_t t2 = sigma0(a) + maj(a,b,c);
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
        state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    }

    uint32_t state_[8];
    uint64_t bit_count_;
    uint8_t  buffer_[BLOCK_SIZE];
    size_t   buffer_len_;
};

// ── HMAC-SHA256 ───────────────────────────────────────────────
class HMAC_SHA256 {
public:
    static constexpr size_t MAC_SIZE = SHA256::DIGEST_SIZE;  // 32 bytes

    /**
     * Compute HMAC-SHA256.
     * @param key      Secret key bytes
     * @param key_len  Length of key
     * @param data     Input data
     * @param data_len Length of data
     * @param mac      Output buffer (32 bytes)
     */
    static void compute(
        const uint8_t* key,  size_t key_len,
        const uint8_t* data, size_t data_len,
        uint8_t mac[MAC_SIZE]
    ) {
        uint8_t k_ipad[SHA256::BLOCK_SIZE] = {};
        uint8_t k_opad[SHA256::BLOCK_SIZE] = {};

        // If key > block size, hash it first
        uint8_t hashed_key[SHA256::DIGEST_SIZE];
        if (key_len > SHA256::BLOCK_SIZE) {
            SHA256::hash(key, key_len, hashed_key);
            key = hashed_key;
            key_len = SHA256::DIGEST_SIZE;
        }

        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);
        for (size_t i = 0; i < SHA256::BLOCK_SIZE; ++i) {
            k_ipad[i] ^= 0x36;
            k_opad[i] ^= 0x5c;
        }

        // Inner hash: SHA256(k_ipad || data)
        uint8_t inner[SHA256::DIGEST_SIZE];
        SHA256 h_inner;
        h_inner.update(k_ipad, SHA256::BLOCK_SIZE);
        h_inner.update(data, data_len);
        h_inner.finalize(inner);

        // Outer hash: SHA256(k_opad || inner)
        SHA256 h_outer;
        h_outer.update(k_opad, SHA256::BLOCK_SIZE);
        h_outer.update(inner, SHA256::DIGEST_SIZE);
        h_outer.finalize(mac);
    }

    /**
     * Constant-time comparison (prevents timing attacks).
     * Returns true if mac_a == mac_b.
     */
    static bool verify(const uint8_t* mac_a, const uint8_t* mac_b) {
        uint8_t diff = 0;
        for (size_t i = 0; i < MAC_SIZE; ++i)
            diff |= mac_a[i] ^ mac_b[i];
        return diff == 0;
    }
};

}  // namespace Crypto
}  // namespace Rex
