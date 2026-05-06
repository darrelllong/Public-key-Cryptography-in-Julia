#!/usr/bin/env julia

# BSD 2-Clause License
#
# Copyright (c) 2021, Darrell Long
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include("primes.jl")

#=
Rabin public-key cryptosystem (Michael O. Rabin, 1979).

Encryption is squaring mod n = p·q; decryption is square root extraction.  The
security of decryption is provably equivalent to integer factorisation — stronger
than the RSA reduction, which is only conjectured equivalent.

The cost of this tight security proof is that squaring mod n has four square roots,
not one, so the decryptor must identify the correct root.  We resolve the ambiguity
with a 32-bit CRC tag embedded in every plaintext: the unique root whose low word
matches _h is the true plaintext; the other three are discarded.

Both primes must satisfy p ≡ q ≡ 3 (mod 4) (Rabin primes) so that the modular
square roots can be computed in closed form as m^((p+1)/4) mod p.

Primes are grown by 16 bits beyond the half-key size to create headroom for the 32-bit
tag prepended to every plaintext before squaring.  Without that extra space the tagged
payload could overflow n, breaking the one-to-one correspondence between plaintexts
and ciphertexts that decryption requires.

Public key:  n = p·q
Private key: (p, q)
=#

function generateKeys(nBits, safe=true)
    x = nBits ÷ 2 + 16 # Make room for the tag (32 bits split across two halves)
    p = rabinPrime(big"2"^x, big"2"^(x + 1) - 1, safe)
    q = rabinPrime(big"2"^x, big"2"^(x + 1) - 1, safe)
    while p == q
        q = rabinPrime(big"2"^(x - 1), big"2"^x - 1, safe)
    end
    (p * q, (p, q))
end

# Arbitrary 32-bit disambiguation tag — same constant used by the Rust crate.
# It is not a cryptographic checksum; its only job is to let the decryptor pick
# the right one of the four square roots that squaring mod n can produce.
const _h = BigInt(2087545471) # crc32("Michael O. Rabin")

#=
Encrypt by squaring the tagged payload mod n.

The message is shifted left by 32 bits and the tag _h is inserted in the low word,
then n÷2 is added so the payload is large enough that its square cannot be trivially
detected as a perfect power without knowing the factors.  Encryption is simply
squaring: c = payload² mod n.
=#

function encrypt(m, n)
    powerMod((m << 32) + _h + n ÷ 2, 2, n) # Insert tag and square (mod n)
end

#=
Recover the plaintext by finding the unique square root that carries the tag.

Squaring mod n = p·q has four square roots.  We compute all four via the Chinese
Remainder Theorem — each factor p and q independently admits two square roots
(±√m mod p and ±√m mod q), which CRT combines into four roots mod n.  Only the
root whose low 32 bits equal _h is the true payload; the other three are discarded.
The original message is the payload >> 32.
=#

function decrypt(m, key)
    (p, q) = key
    n = p * q
    (g, (yP, yQ)) = extendedGCD(p, q)
    mP = powerMod(m, (p + 1) ÷ 4, p)
    mQ = powerMod(m, (q + 1) ÷ 4, q)
    x  = mod(yP * p * mQ + yQ * q * mP, n)
    y  = mod(yP * p * mQ - yQ * q * mP, n)
    msgs = [x - n ÷ 2, n - x - n ÷ 2, y - n ÷ 2, n - y - n ÷ 2]
    for d in msgs
        if d % big"2"^32 == _h
            return d ÷ big"2"^32
        end
    end
    error("Decryption failed: no valid square root with matching CRC tag found.")
end

include("io.jl")

# ── Serialization ─────────────────────────────────────────────────────────────

# Public key: DER SEQUENCE [n]
rabinPublicToBlob(n)          = encodeBigInts(BigInt[n])
rabinPublicFromBlob(blob)     = let r = decodeBigInts(blob); r !== nothing && length(r) == 1 ? r[1] : nothing; end
rabinPublicToPEM(n)           = pemWrap("CRYPTOGRAPHY RABIN PUBLIC KEY", rabinPublicToBlob(n))
function rabinPublicFromPEM(pem)
    blob = pemUnwrap("CRYPTOGRAPHY RABIN PUBLIC KEY", pem)
    blob === nothing ? nothing : rabinPublicFromBlob(blob)
end
rabinPublicToXML(n)           = xmlWrap("RabinPublicKey", [("n", BigInt(n))])
function rabinPublicFromXML(xml)
    r = xmlUnwrap("RabinPublicKey", ["n"], xml)
    r === nothing ? nothing : r[1]
end

# Private key: DER SEQUENCE [n, p, q]
rabinPrivateToBlob(n, p, q)   = encodeBigInts(BigInt[n, p, q])
function rabinPrivateFromBlob(blob)
    r = decodeBigInts(blob)
    r !== nothing && length(r) == 3 ? (r[2], r[3]) : nothing  # return (p, q)
end
rabinPrivateToPEM(n, p, q)    = pemWrap("CRYPTOGRAPHY RABIN PRIVATE KEY", rabinPrivateToBlob(n, p, q))
function rabinPrivateFromPEM(pem)
    blob = pemUnwrap("CRYPTOGRAPHY RABIN PRIVATE KEY", pem)
    blob === nothing ? nothing : rabinPrivateFromBlob(blob)
end
rabinPrivateToXML(n, p, q)    = xmlWrap("RabinPrivateKey", [("n", BigInt(n)), ("p", BigInt(p)), ("q", BigInt(q))])
function rabinPrivateFromXML(xml)
    r = xmlUnwrap("RabinPrivateKey", ["n", "p", "q"], xml)
    r !== nothing && length(r) == 3 ? (r[2], r[3]) : nothing  # return (p, q)
end

if abspath(PROGRAM_FILE) == @__FILE__
    safe = any(a -> a in ("-s", "--safe"), ARGS)

    bits = try
        print("How many bits? ")
        parse(Int64, readline())
    catch
        println("We needed a positive integer!")
        exit(1)
    end

    (n, k) = generateKeys(bits, safe)

    println("n = $n")
    println("lg(n) = $(lg(n))")
    println("key = $k")

    try
        print(">> ")
        for m in eachline()
            if m in ["Quit", "quit", "Q", "q", "Exit", "exit"] break end
            c = encrypt(encode(m), n); println("En[$m] = $c")
            t = decode(decrypt(c, k)); println("De[$c] = $t")
            print(">> ")
        end
    catch
        println("\nSo long!")
    end
end
