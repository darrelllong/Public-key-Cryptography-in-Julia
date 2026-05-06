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
Schmidt-Samoa public-key cryptosystem (Katja Schmidt-Samoa, 2005).

The scheme sits between RSA and Rabin.  Like RSA it uses a public exponent and a
private inverse, but the public modulus n = p²q carries a factor p twice.  This
asymmetry is what enables deterministic decryption: the private computation works
modulo γ = pq, which is strictly smaller than n, so every message in [0, γ)
round-trips exactly.

The conditions (q-1) ∤ p and (p-1) ∤ q are required so that n is invertible
mod λ(n) = lcm(p-1, q-1).  If either condition failed, gcd(n, λ(n)) > 1 and
there would be no private exponent d.

Why d = n⁻¹ mod λ(n)?  By CRT applied to the factorisation n = p²q:
    m^(n·d) ≡ m^1  (mod p)   — because nd ≡ 1 (mod p-1) by choice of d
    m^(n·d) ≡ m^1  (mod q)   — because nd ≡ 1 (mod q-1) by choice of d
so c^d mod γ = m^(nd) mod γ = m, recovering the plaintext.

Public key:  n
Private key: (d, γ)
=#

function generateKeys(nBits, safe=true)
    size = nBits ÷ 2
    low  = big"2"^(size - 1) # Assure the primes are each approximately half of the
    high = big"2"^size - 1   # bits in the modulus.
    f = safe ? safePrime : randomPrime
    p = f(low, high)
    q = f(low, high)
    # Reject q if it would make n non-invertible mod λ(n).
    while p == q || (q - 1) % p == 0 || (p - 1) % q == 0
        q = f(low, high)
    end
    γ = p * q
    𝝺 = lcm(p - 1, q - 1) # Carmichael λ(n) = lcm(λ(p), λ(q)) = lcm(p – 1, q – 1)
    n = p * p * q
    d = inverse(n, 𝝺)
    (n, (d, γ))
end

# The public map m^n mod n is the same one-way function as Cocks, but the
# structure of n = p²q rather than pq is what makes private inversion efficient.
encrypt(m, n) = powerMod(m, n, n)

# Applying d ≡ n⁻¹ (mod λ(n)) undoes the public exponentiation: c^d mod γ = m.
# Reducing mod γ = pq rather than n is correct because the CRT argument above
# guarantees the result lands in [0, γ), where the message must already live.
function decrypt(c, key)
    (d, γ) = key
    powerMod(c, d, γ)
end

include("io.jl")

# ── Serialization ─────────────────────────────────────────────────────────────

# Public key: DER SEQUENCE [n]
ssPublicToBlob(n)        = encodeBigInts(BigInt[n])
ssPublicFromBlob(blob)   = let r = decodeBigInts(blob); r !== nothing && length(r) == 1 ? r[1] : nothing; end
ssPublicToPEM(n)         = pemWrap("CRYPTOGRAPHY SCHMIDT-SAMOA PUBLIC KEY", ssPublicToBlob(n))
function ssPublicFromPEM(pem)
    blob = pemUnwrap("CRYPTOGRAPHY SCHMIDT-SAMOA PUBLIC KEY", pem)
    blob === nothing ? nothing : ssPublicFromBlob(blob)
end
ssPublicToXML(n)         = xmlWrap("SchmidtSamoaPublicKey", [("n", BigInt(n))])
function ssPublicFromXML(xml)
    r = xmlUnwrap("SchmidtSamoaPublicKey", ["n"], xml)
    r === nothing ? nothing : r[1]
end

# Private key: DER SEQUENCE [d, gamma]
ssPrivateToBlob(d, γ)    = encodeBigInts(BigInt[d, γ])
function ssPrivateFromBlob(blob)
    r = decodeBigInts(blob)
    r !== nothing && length(r) == 2 ? (r[1], r[2]) : nothing
end
ssPrivateToPEM(d, γ)     = pemWrap("CRYPTOGRAPHY SCHMIDT-SAMOA PRIVATE KEY", ssPrivateToBlob(d, γ))
function ssPrivateFromPEM(pem)
    blob = pemUnwrap("CRYPTOGRAPHY SCHMIDT-SAMOA PRIVATE KEY", pem)
    blob === nothing ? nothing : ssPrivateFromBlob(blob)
end
ssPrivateToXML(d, γ)     = xmlWrap("SchmidtSamoaPrivateKey", [("d", BigInt(d)), ("gamma", BigInt(γ))])
function ssPrivateFromXML(xml)
    r = xmlUnwrap("SchmidtSamoaPrivateKey", ["d", "gamma"], xml)
    r !== nothing && length(r) == 2 ? (r[1], r[2]) : nothing
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

    (en, de) = generateKeys(bits, safe)

    println("n = $en")
    println("lg(n) = $(lg(en))")
    println("(d, γ) = $de")

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
