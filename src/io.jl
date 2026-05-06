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

#=
Serialization helpers: DER SEQUENCE-of-INTEGERs binary blobs, PEM armor,
and flat-hex XML documents.

Wire formats match the Rust cryptography crate's public_key::io module exactly
so that keys and ciphertexts produced here round-trip with Rust.

Non-RSA field layouts (mirrors Rust io.rs doc comment):
  CocksPublicKey      [n]
  CocksPrivateKey     [pi, q]
  ElGamalPublicKey    [p, exponent_bound, g, b]
  ElGamalPrivateKey   [p, exponent_modulus, a]
  PaillierPublicKey   [n, zeta]
  PaillierPrivateKey  [n, lambda, u]
  RabinPublicKey      [n]
  RabinPrivateKey     [n, p, q]
  SchmidtSamoaPublicKey  [n]
  SchmidtSamoaPrivateKey [d, gamma]

RSA uses PKCS#1 / SPKI / PKCS#8 standard containers (see rsa.jl).
=#

using Base64

# ── DER low-level primitives ──────────────────────────────────────────────────

# Return the minimal big-endian two's-complement encoding of a non-negative
# BigInt for use as a DER positive INTEGER body (prepend 0x00 if the high bit
# is set so the value is not misread as negative).
function _derIntBytes(n::BigInt)::Vector{UInt8}
    n < 0 && error("_derIntBytes: negative values not supported")
    n == 0 && return UInt8[0x00]
    d  = digits(n, base=256)        # least-significant first
    bs = UInt8.(reverse(d))         # most-significant first
    bs[1] & 0x80 != 0 && pushfirst!(bs, 0x00)
    bs
end

# Return the DER length encoding for `len` (short form < 128, long form ≥ 128).
function _derEncLen(len::Int)::Vector{UInt8}
    len < 0x80 && return UInt8[len]
    d  = digits(len, base=256)      # LS first
    bs = UInt8.(reverse(d))         # MS first
    pushfirst!(bs, UInt8(0x80 | length(bs)))
    bs
end

# Decode a DER length starting at `data[pos]` (1-based).
# Returns `(decoded_length, new_pos)` or `nothing`.
function _derDecLen(data::Vector{UInt8}, pos::Int)
    pos > length(data) && return nothing
    first = data[pos]
    first & 0x80 == 0 && return (Int(first), pos + 1)
    count = Int(first & 0x7f)
    count == 0 && return nothing
    pos + count > length(data) && return nothing
    len = 0
    for i in 1:count
        len = (len << 8) | Int(data[pos + i])
    end
    (len, pos + 1 + count)
end

# Build a DER TLV (tag, length, value) byte string.
function _derTLV(tag::UInt8, content::Vector{UInt8})::Vector{UInt8}
    out = UInt8[tag]
    append!(out, _derEncLen(length(content)))
    append!(out, content)
    out
end

_derSequence(content::Vector{UInt8})   = _derTLV(0x30, content)
_derOctetString(content::Vector{UInt8}) = _derTLV(0x04, content)
_derNull()                              = _derTLV(0x05, UInt8[])
_derOID(oid::Vector{UInt8})             = _derTLV(0x06, oid)
_derInteger(n::BigInt)                  = _derTLV(0x02, _derIntBytes(n))
_derIntegerU8(v::UInt8)                 = _derTLV(0x02, UInt8[v])

# DER BIT STRING: leading zero byte marks "no unused bits" in the final octet.
function _derBitString(content::Vector{UInt8})
    _derTLV(0x03, pushfirst!(copy(content), 0x00))
end

# ── DER reader (for PKCS#1 / SPKI / PKCS#8 parsing) ─────────────────────────

mutable struct _DerReader
    data::Vector{UInt8}
    pos::Int
end

_derReaderDone(r::_DerReader) = r.pos > length(r.data)

function _readTLV(r::_DerReader, tag::UInt8)::Union{Vector{UInt8}, Nothing}
    r.pos > length(r.data)  && return nothing
    r.data[r.pos] != tag    && return nothing
    r.pos += 1
    res = _derDecLen(r.data, r.pos)
    res === nothing          && return nothing
    (len, new_pos) = res
    r.pos = new_pos
    r.pos + len - 1 > length(r.data) && return nothing
    content = r.data[r.pos : r.pos + len - 1]
    r.pos += len
    content
end

function _readBigInt(r::_DerReader)::Union{BigInt, Nothing}
    c = _readTLV(r, 0x02)
    (c === nothing || isempty(c)) && return nothing
    c[1] & 0x80 != 0 && return nothing      # negative not allowed
    body = if length(c) > 1 && c[1] == 0x00
        c[2] & 0x80 == 0 && return nothing  # non-minimal encoding
        c[2:end]
    else
        c
    end
    reduce((acc, b) -> acc * 256 + BigInt(b), body; init=BigInt(0))
end

function _readSmallUInt(r::_DerReader)::Union{UInt8, Nothing}
    v = _readBigInt(r)
    v === nothing              && return nothing
    ndigits(v, base=256) > 1  && return nothing
    UInt8(v)
end

# ── General public-key blob format: DER SEQUENCE of positive INTEGERs ────────

"""
    encodeBigInts(fields) → Vector{UInt8}

Encode a vector of non-negative BigInts as a DER SEQUENCE of INTEGERs.
Matches `encode_biguints` in the Rust crate's `public_key::io` module.
"""
function encodeBigInts(fields::Vector{BigInt})::Vector{UInt8}
    body = UInt8[]
    for f in fields
        bs = _derIntBytes(f)
        push!(body, 0x02)
        append!(body, _derEncLen(length(bs)))
        append!(body, bs)
    end
    _derTLV(0x30, body)
end

"""
    decodeBigInts(blob) → Vector{BigInt} or nothing

Decode a DER SEQUENCE of positive INTEGERs.
Matches `decode_biguints` in the Rust crate's `public_key::io` module.
"""
function decodeBigInts(blob::Vector{UInt8})::Union{Vector{BigInt}, Nothing}
    isempty(blob)      && return nothing
    blob[1] != 0x30    && return nothing

    r = _derDecLen(blob, 2)
    r === nothing      && return nothing
    (seq_len, pos) = r
    pos + seq_len - 1 != length(blob) && return nothing

    end_pos = pos + seq_len - 1
    result  = BigInt[]

    while pos <= end_pos
        pos > length(blob)  && return nothing
        blob[pos] != 0x02   && return nothing
        pos += 1

        r2 = _derDecLen(blob, pos)
        r2 === nothing      && return nothing
        (ilen, pos) = r2
        pos + ilen - 1 > length(blob) && return nothing

        field = blob[pos : pos + ilen - 1]
        pos += ilen

        isempty(field)              && return nothing
        field[1] & 0x80 != 0        && return nothing  # negative

        body = if length(field) > 1 && field[1] == 0x00
            field[2] & 0x80 == 0    && return nothing  # non-minimal
            field[2:end]
        else
            field
        end

        push!(result, reduce((acc, b) -> acc * 256 + BigInt(b), body; init=BigInt(0)))
    end
    result
end

# ── PEM armor ─────────────────────────────────────────────────────────────────

"""
    pemWrap(label, blob) → String

Wrap binary `blob` in PEM text armor with the given label.
Base64 lines are 64 characters wide, matching the Rust crate.
"""
function pemWrap(label::String, blob::Vector{UInt8})::String
    b64 = base64encode(blob)
    out = "-----BEGIN $(label)-----\n"
    i = 1
    while i <= length(b64)
        out *= SubString(b64, i, min(i + 63, length(b64))) * "\n"
        i += 64
    end
    out * "-----END $(label)-----\n"
end

"""
    pemUnwrap(label, pem) → Vector{UInt8} or nothing

Decode PEM text armor with the given label and return the binary payload.
"""
function pemUnwrap(label::String, pem::String)::Union{Vector{UInt8}, Nothing}
    lines = split(rstrip(pem), '\n')
    isempty(lines) && return nothing
    lines[1] != "-----BEGIN $(label)-----" && return nothing
    parts = String[]
    for line in lines[2:end]
        s = strip(line)
        s == "-----END $(label)-----" && return base64decode(join(parts))
        isempty(s) || push!(parts, s)
    end
    nothing
end

# ── Uppercase hex encode / decode ─────────────────────────────────────────────

const _HEX_DIGITS = "0123456789ABCDEF"

"""
    hexEncodeUpper(n) → String

Encode a non-negative BigInt as an even-length uppercase hex string (no "0x").
Matches `hex_encode_upper` in the Rust crate's `public_key::io` module.
"""
function hexEncodeUpper(n::BigInt)::String
    n == 0 && return "00"
    d  = digits(n, base=256)    # LS first
    bs = UInt8.(reverse(d))     # MS first
    buf = IOBuffer()
    for b in bs
        write(buf, _HEX_DIGITS[(b >> 4)  + 1])
        write(buf, _HEX_DIGITS[(b & 0x0f) + 1])
    end
    String(take!(buf))
end

function _hexNibble(c::Char)::Union{Int, Nothing}
    '0' <= c <= '9' && return Int(c) - Int('0')
    'A' <= c <= 'F' && return Int(c) - Int('A') + 10
    'a' <= c <= 'f' && return Int(c) - Int('a') + 10
    nothing
end

"""
    hexDecodeBigInt(s) → BigInt or nothing

Decode an even-length uppercase/lowercase hex string to a BigInt.
The single-character shorthand "0" is also accepted for zero.
"""
function hexDecodeBigInt(s::String)::Union{BigInt, Nothing}
    s = strip(s)
    isempty(s)          && return nothing
    s == "0"            && return BigInt(0)
    length(s) % 2 != 0 && return nothing
    n = BigInt(0)
    for i in 1:2:length(s)
        hi = _hexNibble(s[i]);   hi === nothing && return nothing
        lo = _hexNibble(s[i+1]); lo === nothing && return nothing
        n = n * 256 + BigInt((hi << 4) | lo)
    end
    n
end

# ── Flat-hex XML ──────────────────────────────────────────────────────────────

"""
    xmlWrap(root, pairs) → String

Produce the compact flat-XML format used by the Rust crate:
`<Root><field1>HEXHEX</field1>…</Root>`.
No whitespace between elements; integer values in uppercase hex.
`pairs` is an iterable of `(field_name, BigInt_value)`.
"""
function xmlWrap(root::String, pairs)::String
    out = "<$(root)>"
    for (name, val) in pairs
        out *= "<$(name)>$(hexEncodeUpper(BigInt(val)))</$(name)>"
    end
    out * "</$(root)>"
end

"""
    xmlUnwrap(root, fieldNames, xml) → Vector{BigInt} or nothing

Parse the compact flat-XML format. The root tag, field names, and order must
all match exactly. Returns `nothing` on any mismatch or trailing content.
"""
function xmlUnwrap(root::String, fieldNames::Vector{String}, xml::String)::Union{Vector{BigInt}, Nothing}
    xml = strip(xml)
    open_root  = "<$(root)>"
    close_root = "</$(root)>"
    startswith(xml, open_root)  || return nothing
    endswith(xml,   close_root) || return nothing
    inner = xml[length(open_root)+1 : length(xml)-length(close_root)]

    result = BigInt[]
    for name in fieldNames
        otag = "<$(name)>"
        ctag = "</$(name)>"
        startswith(inner, otag) || return nothing
        inner = inner[length(otag)+1:end]
        cp = findfirst(ctag, inner)
        cp === nothing          && return nothing
        v = hexDecodeBigInt(String(inner[1:cp.start-1]))
        v === nothing           && return nothing
        push!(result, v)
        inner = inner[cp.stop+1:end]
    end
    isempty(inner) || return nothing
    result
end

# ── RSA OID constant (rsaEncryption 1.2.840.113549.1.1.1) ────────────────────

const _RSA_OID = UInt8[0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01]
