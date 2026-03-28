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
ElGamal public-key cryptosystem (Taher ElGamal, 1985).

Security rests on the discrete logarithm problem: given p, r, and b = rᵃ mod p, it
is computationally infeasible to recover the secret exponent a.  The scheme is
probabilistic — each encryption draws a fresh random session key k, so the same
plaintext produces a different ciphertext every time.

Key generation picks a k-bit prime p and a generator r of a large subgroup of Z_p*.
The lower bound r ≥ 2^16 + 1 is not strictly required but avoids degenerate small
generators that expose structure.  The secret exponent a is drawn from the upper half
of [0, p-1] so it is large enough to resist baby-step / giant-step attacks sized for
small exponents.

Public key:  (p, r, b)  where b = rᵃ mod p
Private key: (p, a)
=#

function generateKeys(k, safe=true)
    low  = big"2"^(k - 1)
    high = big"2"^k - 1
    f = safe ? safePrime : randomPrime
    p = f(low, high)
    r = groupGenerator(big"2"^16 + 1, p)
    a = rand((p - 1) ÷ 2:p - 1)
    b = powerMod(r, a, p)
    ((p, a), (p, r, b))
end

#=
Encrypt m by masking it with b^k, then publishing the hint γ = r^k.

The session key k is chosen freshly at random so the ciphertext (γ, δ) is
computationally indistinguishable from a random pair in Z_p × Z_p to anyone who
does not know a.  The mask b^k = r^(ak) is only computable from γ by someone who
knows a, because computing a from b = r^a is the discrete-log problem.
=#

function encrypt(m, key)
    (p, r, b) = key
    k = rand(BigInt(1):p - 2)
    𝛾 = powerMod(r, k, p)
    𝛿 = (m * powerMod(b, k, p)) % p
    (𝛾, 𝛿)
end

#=
Decrypt by stripping the mask: δ · γ^(p−1−a) ≡ m (mod p).

Fermat's little theorem gives γ^(p−1) ≡ 1 (mod p), so
    γ^(p−1−a) = γ^(−a) mod p = r^(−ak) mod p.
Multiplying δ = m · r^(ak) by this inverse cancels the mask and recovers m.
=#

function decrypt(m, key)
    (p, a) = key
    (𝛾, 𝛿) = m
    (powerMod(𝛾, p - 1 - a, p) * 𝛿) % p
end

include("io.jl")

# ── Serialization ─────────────────────────────────────────────────────────────
# Public key layout: [p, exponent_bound, generator, public_component] = [p, p-1, g, b]
# Private key layout: [p, exponent_modulus, a] = [p, p-1, a]

elgamalPublicToBlob(p, g, b)      = encodeBigInts(BigInt[p, p - 1, g, b])
function elgamalPublicFromBlob(blob)
    r = decodeBigInts(blob)
    r !== nothing && length(r) == 4 ? (r[1], r[3], r[4]) : nothing  # (p, g, b)
end
elgamalPublicToPEM(p, g, b)       = pemWrap("CRYPTOGRAPHY ELGAMAL PUBLIC KEY", elgamalPublicToBlob(p, g, b))
function elgamalPublicFromPEM(pem)
    blob = pemUnwrap("CRYPTOGRAPHY ELGAMAL PUBLIC KEY", pem)
    blob === nothing ? nothing : elgamalPublicFromBlob(blob)
end
function elgamalPublicToXML(p, g, b)
    xmlWrap("ElGamalPublicKey", [("p", BigInt(p)), ("exponent-bound", BigInt(p - 1)),
                                  ("generator", BigInt(g)), ("public-component", BigInt(b))])
end
function elgamalPublicFromXML(xml)
    r = xmlUnwrap("ElGamalPublicKey", ["p", "exponent-bound", "generator", "public-component"], xml)
    r !== nothing && length(r) == 4 ? (r[1], r[3], r[4]) : nothing  # (p, g, b)
end

elgamalPrivateToBlob(p, a)        = encodeBigInts(BigInt[p, p - 1, a])
function elgamalPrivateFromBlob(blob)
    r = decodeBigInts(blob)
    r !== nothing && length(r) == 3 ? (r[1], r[3]) : nothing  # (p, a)
end
elgamalPrivateToPEM(p, a)         = pemWrap("CRYPTOGRAPHY ELGAMAL PRIVATE KEY", elgamalPrivateToBlob(p, a))
function elgamalPrivateFromPEM(pem)
    blob = pemUnwrap("CRYPTOGRAPHY ELGAMAL PRIVATE KEY", pem)
    blob === nothing ? nothing : elgamalPrivateFromBlob(blob)
end
function elgamalPrivateToXML(p, a)
    xmlWrap("ElGamalPrivateKey", [("p", BigInt(p)), ("exponent-modulus", BigInt(p - 1)), ("a", BigInt(a))])
end
function elgamalPrivateFromXML(xml)
    r = xmlUnwrap("ElGamalPrivateKey", ["p", "exponent-modulus", "a"], xml)
    r !== nothing && length(r) == 3 ? (r[1], r[3]) : nothing  # (p, a)
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

    (prv, pub) = generateKeys(bits, safe)

    println("pub = $pub")
    println("prv = $prv")

    try
        print(">> ")
        for m in eachline()
            if m in ["Quit", "quit", "Q", "q", "Exit", "exit"] break end
            c = encrypt(encode(m), pub); println("En[$m] = $c")
            t = decode(decrypt(c, prv)); println("De[$c] = $t")
            print(">> ")
        end
    catch
        println("\nSo long!")
    end
end
