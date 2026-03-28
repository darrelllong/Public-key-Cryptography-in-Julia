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
Clifford Cocks's original public-key cryptosystem (CESG memo, 1973).

This predates RSA by five years.  It was classified as secret by GCHQ and not
published until 1997.  The arithmetic is simpler than RSA but produces ciphertexts
as large as the modulus, so it is impractical for bulk data — its interest is
historical and pedagogical.

Key generation: choose distinct primes p < q, then set π = p⁻¹ mod (q-1).
We enforce p < q so that q is unambiguously the "larger" prime stored in the
private key — the convention the serialized form relies on.

Why π = p⁻¹ mod (q-1)?  Encryption raises m to the n-th power mod n.
By Fermat's little theorem, m^(q-1) ≡ 1 mod q, so the exponent n = pq reduces
to n mod (q-1) = pq mod (q-1).  Since q ≡ 1 (mod q-1), this is just p.
Decryption therefore computes c^π mod q = m^(p·π) mod q = m^1 mod q = m,
recovering the original plaintext (provided m < q).

Public key:  n
Private key: (π, q)
=#

function generateKeys(nBits, safe=true)
    size = nBits ÷ 2
    low  = big"2"^(size - 1) # Assure the primes are each approximately half of the
    high = big"2"^size - 1   # bits in the modulus.
    f = safe ? safePrime : randomPrime
    p = f(low, high)
    q = f(low, high)
    while p == q
        q = f(low, high)
    end
    if p > q
        p, q = q, p  # Ensure p < q so that q is unambiguously the stored private prime.
    end
    π = inverse(p, q - 1)
    while π === nothing  # Retry if p is not invertible mod q – 1 (gcd(p, q-1) ≠ 1).
        q = f(low, high)
        while p == q
            q = f(low, high)
        end
        if p > q
            p, q = q, p
        end
        π = inverse(p, q - 1)
    end
    n = p * q
    (n, (π, q))
end

# Raise m to the n-th power mod n.  The security of the scheme relies on the
# difficulty of computing n-th roots modulo a product of two unknown primes.
encrypt(m, n) = powerMod(m, n, n)

# Recover m by reducing the exponent: c^π mod q = m^(n·π) mod q = m^1 mod q = m.
# The exponent chain works because n ≡ p (mod q-1) and π ≡ p⁻¹ (mod q-1).
function decrypt(c, key)
    (π, q) = key
    powerMod(c, π, q)
end

include("io.jl")

# ── Serialization ─────────────────────────────────────────────────────────────

# Public key: DER SEQUENCE [n]
cocksPublicToBlob(n)         = encodeBigInts(BigInt[n])
cocksPublicFromBlob(blob)    = let r = decodeBigInts(blob); r !== nothing && length(r) == 1 ? r[1] : nothing; end
cocksPublicToPEM(n)          = pemWrap("CRYPTOGRAPHY COCKS PUBLIC KEY", cocksPublicToBlob(n))
function cocksPublicFromPEM(pem)
    blob = pemUnwrap("CRYPTOGRAPHY COCKS PUBLIC KEY", pem)
    blob === nothing ? nothing : cocksPublicFromBlob(blob)
end
cocksPublicToXML(n)          = xmlWrap("CocksPublicKey", [("n", BigInt(n))])
function cocksPublicFromXML(xml)
    r = xmlUnwrap("CocksPublicKey", ["n"], xml)
    r === nothing ? nothing : r[1]
end

# Private key: DER SEQUENCE [pi, q]
cocksPrivateToBlob(π, q)     = encodeBigInts(BigInt[π, q])
function cocksPrivateFromBlob(blob)
    r = decodeBigInts(blob)
    r !== nothing && length(r) == 2 ? (r[1], r[2]) : nothing
end
cocksPrivateToPEM(π, q)      = pemWrap("CRYPTOGRAPHY COCKS PRIVATE KEY", cocksPrivateToBlob(π, q))
function cocksPrivateFromPEM(pem)
    blob = pemUnwrap("CRYPTOGRAPHY COCKS PRIVATE KEY", pem)
    blob === nothing ? nothing : cocksPrivateFromBlob(blob)
end
cocksPrivateToXML(π, q)      = xmlWrap("CocksPrivateKey", [("pi", BigInt(π)), ("q", BigInt(q))])
function cocksPrivateFromXML(xml)
    r = xmlUnwrap("CocksPrivateKey", ["pi", "q"], xml)
    r !== nothing && length(r) == 2 ? (r[1], r[2]) : nothing
end

if abspath(PROGRAM_FILE) == @__FILE__
    safe = false
    for arg in ARGS
        if arg == "-s" || arg == "--safe"
            safe = true
        end
    end

    try
        print("How many bits? ")
        bits = parse(Int64, readline())
    catch
        println("We needed a positive integer!")
        exit(1)
    end

    (en, de) = generateKeys(bits, safe)

    println("n = $en")
    println("lg(n) = $(lg(en))")
    println("(π, q) = $de")

    try
        print(">> ")
        for m in eachline()
            if m in ["Quit", "quit", "Q", "q", "Exit", "exit"] break end
            c = encrypt(encode(m), en); println("En[$m] = $c")
            t = decode(decrypt(c, de)); println("De[$c] = $t")
            print(">> ")
        end
    catch
        println("\nSo long!")
    end
end
