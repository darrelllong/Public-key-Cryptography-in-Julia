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

using Base64

#=
Generates the RSA key pairs: (e, n) and (d, n).
You have the option of using safe primes, though this is probably unnecessary.

Each of the generated primes p and q will each have approximately 1/2 of the bits.

Instead of 𝜑(n), we use λ(n) for the modulus. λ is slightly more efficient.

         16
e will be 2  + 1 unless gcd(e, λ) ≠ 1, in which case it will be slightly larger.

Return the triple (e, d, n)
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
    𝝺 = lcm(p - 1, q - 1) # Carmichael 𝝺(n) = lcm(𝝺(p), 𝝺(q)) = lcm(p - 1, q - 1)
    k = 16
    e = big"2"^k + 1             # Default public exponent
    while gcd(e, 𝝺) != 1         # Happens only if we are very, very unlucky
        k += 1
        e = big"2"^k + 1
    end
    d = inverse(e, 𝝺)            # The private exponent
    n = p * q                    # The modulus
    (e, d, n)
end

encrypt(m, e, n) = powerMod(m, e, n)

decrypt(c, d, n) = powerMod(c, d, n)

# The number of bytes required to hold n.

byteLength(n::BigInt) = (ndigits(n, base=2) ÷ 8) + (ndigits(n, base=2) % 8 != 0 ? 1 : 0)

#=
Create a public SSH key string from e and n.

The format of an ssh key is:
    [key-type (always "ssh-rsa" here)] [e] [n]
Where each field is made up of:
    a 32-bit integer -- the length n of the field; and
    n bytes -- the contents of the field.
=#

function publicKeyToStr(e, n)
    key_type = b"ssh-rsa"
    key = UInt8[]

    eLen = byteLength(e)
    nLen = byteLength(n)

    append!(key, reinterpret(UInt8, [hton(UInt32(length(key_type)))]))
    append!(key, key_type)
    append!(key, reinterpret(UInt8, [hton(UInt32(eLen))]))
    append!(key, digits(e, base=256, pad=eLen)[end:-1:1])
    append!(key, reinterpret(UInt8, [hton(UInt32(nLen))]))
    append!(key, digits(n, base=256, pad=nLen)[end:-1:1])

    "ssh-rsa " * base64encode(key)
end

#=
Retrieve (e, n) from a public ssh key string.
=#

function publicKeyFromStr(keyStr)
    @assert startswith(keyStr, "ssh-rsa")
    parts = split(keyStr, " ")
    key = base64decode(parts[2])
    i = 1

    # Read key type
    len = Int(key[i]) << 24 | Int(key[i+1]) << 16 | Int(key[i+2]) << 8 | Int(key[i+3])
    i += 4 + len

    # Read e
    len = Int(key[i]) << 24 | Int(key[i+1]) << 16 | Int(key[i+2]) << 8 | Int(key[i+3])
    i += 4
    e = reduce((acc, b) -> acc * 256 + BigInt(b), key[i:i+len-1], init=BigInt(0))
    i += len

    # Read n
    len = Int(key[i]) << 24 | Int(key[i+1]) << 16 | Int(key[i+2]) << 8 | Int(key[i+3])
    i += 4
    n = reduce((acc, b) -> acc * 256 + BigInt(b), key[i:i+len-1], init=BigInt(0))

    (e, n)
end

include("io.jl")

#=
Extended key generation that also returns the primes p and q, needed for
PKCS#1 CRT fields.  The arithmetic is identical to generateKeys/2.
=#
function generateRsaFullKeys(nBits, safe=true)
    size = nBits ÷ 2
    low  = big"2"^(size - 1)
    high = big"2"^size - 1
    f = safe ? safePrime : randomPrime
    p = f(low, high)
    q = f(low, high)
    while p == q
        q = f(low, high)
    end
    𝝺 = lcm(p - 1, q - 1)
    k = 16
    e = big"2"^k + 1
    while gcd(e, 𝝺) != 1
        k += 1
        e = big"2"^k + 1
    end
    d = inverse(e, 𝝺)
    n = p * q
    (e, d, n, p, q)
end

# ── RSA PKCS#1 / SPKI / PKCS#8 serialization ─────────────────────────────────

# PKCS#1 public key:  SEQUENCE { n INTEGER, e INTEGER }
function rsaPublicToPkcs1Der(e, n)
    body = UInt8[]
    append!(body, _derInteger(BigInt(n)))
    append!(body, _derInteger(BigInt(e)))
    _derSequence(body)
end

function rsaPublicFromPkcs1Der(der::Vector{UInt8})
    outer = _DerReader(der, 1)
    seq = _readTLV(outer, 0x30)
    seq === nothing || !_derReaderDone(outer) && return nothing
    r = _DerReader(seq, 1)
    n = _readBigInt(r);  n === nothing && return nothing
    e = _readBigInt(r);  e === nothing && return nothing
    _derReaderDone(r) || return nothing
    e > BigInt(1) || return nothing
    (e, n)
end

# SPKI: SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { PKCS1 } }
function rsaPublicToSpkiDer(e, n)
    pkcs1 = rsaPublicToPkcs1Der(e, n)
    alg   = UInt8[]
    append!(alg, _derOID(_RSA_OID))
    append!(alg, _derNull())
    body  = UInt8[]
    append!(body, _derSequence(alg))
    append!(body, _derBitString(pkcs1))
    _derSequence(body)
end

function rsaPublicFromSpkiDer(der::Vector{UInt8})
    outer = _DerReader(der, 1)
    seq = _readTLV(outer, 0x30)
    seq === nothing || !_derReaderDone(outer) && return nothing
    r = _DerReader(seq, 1)
    alg_seq = _readTLV(r, 0x30);    alg_seq === nothing && return nothing
    bs      = _readTLV(r, 0x03);    bs === nothing && return nothing
    _derReaderDone(r) || return nothing
    isempty(bs) || bs[1] != 0x00    && return nothing
    alg_r = _DerReader(alg_seq, 1)
    oid   = _readTLV(alg_r, 0x06);  oid === nothing && return nothing
    _readTLV(alg_r, 0x05)           === nothing && return nothing
    _derReaderDone(alg_r) || return nothing
    oid != _RSA_OID                 && return nothing
    rsaPublicFromPkcs1Der(collect(bs[2:end]))
end

# PKCS#1 private key: SEQUENCE { 0, n, e, d, p, q, d_p, d_q, q_inv }
function rsaPrivateToPkcs1Der(e, d, n, p, q)
    d_p   = d % (p - 1)
    d_q   = d % (q - 1)
    q_inv = inverse(q, p)
    body  = UInt8[]
    append!(body, _derIntegerU8(0x00))      # version = 0
    append!(body, _derInteger(BigInt(n)))
    append!(body, _derInteger(BigInt(e)))
    append!(body, _derInteger(BigInt(d)))
    append!(body, _derInteger(BigInt(p)))
    append!(body, _derInteger(BigInt(q)))
    append!(body, _derInteger(BigInt(d_p)))
    append!(body, _derInteger(BigInt(d_q)))
    append!(body, _derInteger(BigInt(q_inv)))
    _derSequence(body)
end

function rsaPrivateFromPkcs1Der(der::Vector{UInt8})
    outer = _DerReader(der, 1)
    seq = _readTLV(outer, 0x30)
    seq === nothing || !_derReaderDone(outer) && return nothing
    r = _DerReader(seq, 1)
    ver = _readSmallUInt(r);  ver === nothing || ver != 0x00 && return nothing
    n   = _readBigInt(r);  n === nothing && return nothing
    e   = _readBigInt(r);  e === nothing && return nothing
    d   = _readBigInt(r);  d === nothing && return nothing
    p   = _readBigInt(r);  p === nothing && return nothing
    q   = _readBigInt(r);  q === nothing && return nothing
    _readBigInt(r)  # d_p  — consumed but not returned
    _readBigInt(r)  # d_q
    _readBigInt(r)  # q_inv
    _derReaderDone(r) || return nothing
    (e, d, n, p, q)
end

# PKCS#8: SEQUENCE { 0, SEQUENCE { OID, NULL }, OCTET STRING { PKCS1 } }
function rsaPrivateToPkcs8Der(e, d, n, p, q)
    pkcs1 = rsaPrivateToPkcs1Der(e, d, n, p, q)
    alg   = UInt8[]
    append!(alg, _derOID(_RSA_OID))
    append!(alg, _derNull())
    body  = UInt8[]
    append!(body, _derIntegerU8(0x00))
    append!(body, _derSequence(alg))
    append!(body, _derOctetString(pkcs1))
    _derSequence(body)
end

function rsaPrivateFromPkcs8Der(der::Vector{UInt8})
    outer = _DerReader(der, 1)
    seq = _readTLV(outer, 0x30)
    seq === nothing || !_derReaderDone(outer) && return nothing
    r = _DerReader(seq, 1)
    ver     = _readSmallUInt(r);   ver === nothing || ver != 0x00 && return nothing
    alg_seq = _readTLV(r, 0x30);  alg_seq === nothing && return nothing
    inner   = _readTLV(r, 0x04);  inner === nothing && return nothing
    _derReaderDone(r) || return nothing
    alg_r = _DerReader(alg_seq, 1)
    oid   = _readTLV(alg_r, 0x06);  oid === nothing && return nothing
    _readTLV(alg_r, 0x05)           === nothing && return nothing
    _derReaderDone(alg_r) || return nothing
    oid != _RSA_OID                  && return nothing
    rsaPrivateFromPkcs1Der(inner)
end

# PEM helpers
rsaPublicToPkcs1PEM(e, n)          = pemWrap("RSA PUBLIC KEY",  rsaPublicToPkcs1Der(e, n))
rsaPublicFromPkcs1PEM(pem)         = let b = pemUnwrap("RSA PUBLIC KEY",  pem); b === nothing ? nothing : rsaPublicFromPkcs1Der(b); end
rsaPublicToSpkiPEM(e, n)           = pemWrap("PUBLIC KEY",       rsaPublicToSpkiDer(e, n))
rsaPublicFromSpkiPEM(pem)          = let b = pemUnwrap("PUBLIC KEY",       pem); b === nothing ? nothing : rsaPublicFromSpkiDer(b); end
rsaPrivateToPkcs1PEM(e,d,n,p,q)    = pemWrap("RSA PRIVATE KEY", rsaPrivateToPkcs1Der(e,d,n,p,q))
rsaPrivateFromPkcs1PEM(pem)        = let b = pemUnwrap("RSA PRIVATE KEY", pem); b === nothing ? nothing : rsaPrivateFromPkcs1Der(b); end
rsaPrivateToPkcs8PEM(e,d,n,p,q)    = pemWrap("PRIVATE KEY",      rsaPrivateToPkcs8Der(e,d,n,p,q))
rsaPrivateFromPkcs8PEM(pem)        = let b = pemUnwrap("PRIVATE KEY",      pem); b === nothing ? nothing : rsaPrivateFromPkcs8Der(b); end

# XML helpers  (field order matches Rust rsa_io.rs)
rsaPublicToXML(e, n)               = xmlWrap("RsaPublicKey",  [("e", BigInt(e)), ("n", BigInt(n))])
function rsaPublicFromXML(xml)
    r = xmlUnwrap("RsaPublicKey", ["e", "n"], xml)
    r !== nothing && length(r) == 2 ? (r[1], r[2]) : nothing
end
rsaPrivateToXML(e, d, n, p, q)     = xmlWrap("RsaPrivateKey", [("e", BigInt(e)), ("d", BigInt(d)),
                                                                  ("n", BigInt(n)), ("p", BigInt(p)), ("q", BigInt(q))])
function rsaPrivateFromXML(xml)
    r = xmlUnwrap("RsaPrivateKey", ["e", "d", "n", "p", "q"], xml)
    r !== nothing && length(r) == 5 ? (r[1], r[2], r[3], r[4], r[5]) : nothing
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

    (e, d, n) = generateKeys(bits, safe)

    println("e = $e")
    println("d = $d")
    println("lg(d) = $(lg(d))")
    println("n = $n")
    println("lg(n) = $(lg(n))")

    try
        print(">> ")
        for m in eachline()
            if m in ["Quit", "quit", "Q", "q", "Exit", "exit"] break end
            c = encrypt(encode(m), e, n); println("En[$m] = $c")
            t = decode(decrypt(c, d, n)); println("De[$c] = $t")
            print(">> ")
        end
    catch
        println("\nSo long!")
    end
end
