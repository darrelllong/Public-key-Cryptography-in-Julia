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
Paillier's public-key cryptosystem based on composite degree residuosity classes
(Pascal Paillier, 1999).

Security rests on the decisional composite residuosity assumption: it is hard to
decide whether a random element of Z_{n²}* is an n-th power (a "residue").
Encryption hides the message in a residue class; only the holder of the prime
factors can identify which class.

The scheme is additively homomorphic: multiplying two ciphertexts mod n² yields
an encryption of the sum of the plaintexts. This lets computations be performed
on encrypted data without ever decrypting it.
=#

L(x, n) = (x - 1) ÷ n

#=
Generate a Paillier key pair of nBits strength.

We require gcd(n, (p-1)(q-1)) = 1, which almost certainly holds for random
primes; the loop guards against the rare failure.

ζ = n+1 is the standard choice because the binomial theorem gives
    (n+1)^m ≡ 1 + mn  (mod n²)
making the L map exact: L((n+1)^m mod n²) = m directly.  Any ζ with order n
in the group of n-th residues would work, but this one avoids an extra modular
inversion during key generation.

u = L(ζ^λ mod n², n)⁻¹ mod n is precomputed so each decryption needs only one
modular exponentiation and two multiplications instead of an extra inversion.

Public key:  (n, ζ)
Private key: (n, λ, u)
=#

function generateKeys(nBits, safe=true)
    k  = nBits ÷ 2
    lo = big"2"^(k - 1) # Assure the primes are approximately equal in size.
    hi = big"2"^k - 1
    f  = safe ? safePrime : randomPrime
    g  = BigInt(0)
    local p, q, n
    # Should only loop once, but we have to be certain.
    while g != 1
        p = f(lo, hi)
        q = f(lo, hi)
        n = p * q
        g = gcd(n, (p - 1) * (q - 1))
    end
    𝝺 = lcm(p - 1, q - 1) # Carmichael λ(n) = lcm(p-1, q-1); smaller than φ(n) but equally usable
    𝜻 = n + 1              # Standard choice: (n+1)^m ≡ 1 + mn (mod n²)
    u = inverse(L(powerMod(𝜻, 𝝺, n * n), n), n)
    ((n, 𝝺, u), (n, 𝜻))
end

#=
Encrypt plaintext m as c = ζ^m · r^n  mod n².

The random nonce r ∈ [1, n-1] blinds the ciphertext so that encrypting the
same message twice produces different outputs (semantic security).  Different
nonces are residues of different cosets of the n-th-power subgroup, but all
decrypt identically because λ annihilates every n-th power: r^(nλ) ≡ 1 mod n².
=#

function encrypt(m, key)
    (n, 𝜻) = key
    r = rand(BigInt(1):n - 1)
    (powerMod(𝜻, m, n * n) * powerMod(r, n, n * n)) % (n * n)
end

#=
Decrypt by computing m = L(c^λ mod n²) · u  mod n.

Raising c to λ kills the blinding nonce (r^(nλ) ≡ 1 mod n²), leaving only
ζ^(mλ) mod n² = (1 + mn)^λ (using our choice ζ = n+1 and the binomial theorem).
After applying L this gives mλ mod n; multiplying by u = λ⁻¹ mod n recovers m.
=#

function decrypt(c, key)
    (n, 𝝺, u) = key
    (L(powerMod(c, 𝝺, n * n), n) * u) % n
end

include("io.jl")

# ── Serialization ─────────────────────────────────────────────────────────────

# Public key: DER SEQUENCE [n, zeta]
paillierPublicToBlob(n, 𝜻)     = encodeBigInts(BigInt[n, 𝜻])
function paillierPublicFromBlob(blob)
    r = decodeBigInts(blob)
    r !== nothing && length(r) == 2 ? (r[1], r[2]) : nothing
end
paillierPublicToPEM(n, 𝜻)      = pemWrap("CRYPTOGRAPHY PAILLIER PUBLIC KEY", paillierPublicToBlob(n, 𝜻))
function paillierPublicFromPEM(pem)
    blob = pemUnwrap("CRYPTOGRAPHY PAILLIER PUBLIC KEY", pem)
    blob === nothing ? nothing : paillierPublicFromBlob(blob)
end
paillierPublicToXML(n, 𝜻)      = xmlWrap("PaillierPublicKey", [("n", BigInt(n)), ("zeta", BigInt(𝜻))])
function paillierPublicFromXML(xml)
    r = xmlUnwrap("PaillierPublicKey", ["n", "zeta"], xml)
    r !== nothing && length(r) == 2 ? (r[1], r[2]) : nothing
end

# Private key: DER SEQUENCE [n, lambda, u]
paillierPrivateToBlob(n, 𝝺, u)  = encodeBigInts(BigInt[n, 𝝺, u])
function paillierPrivateFromBlob(blob)
    r = decodeBigInts(blob)
    r !== nothing && length(r) == 3 ? (r[1], r[2], r[3]) : nothing
end
paillierPrivateToPEM(n, 𝝺, u)   = pemWrap("CRYPTOGRAPHY PAILLIER PRIVATE KEY", paillierPrivateToBlob(n, 𝝺, u))
function paillierPrivateFromPEM(pem)
    blob = pemUnwrap("CRYPTOGRAPHY PAILLIER PRIVATE KEY", pem)
    blob === nothing ? nothing : paillierPrivateFromBlob(blob)
end
paillierPrivateToXML(n, 𝝺, u)   = xmlWrap("PaillierPrivateKey", [("n", BigInt(n)), ("lambda", BigInt(𝝺)), ("u", BigInt(u))])
function paillierPrivateFromXML(xml)
    r = xmlUnwrap("PaillierPrivateKey", ["n", "lambda", "u"], xml)
    r !== nothing && length(r) == 3 ? (r[1], r[2], r[3]) : nothing
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

    prv, pub = generateKeys(bits, safe)

    println("pub = $pub")
    println("prv = $prv")
    println("lg(n) = $(lg(pub[1]))")

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
