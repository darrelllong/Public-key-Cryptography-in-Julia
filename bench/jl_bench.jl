#!/usr/bin/env julia
# Per-iteration timing driver for the Julia cryptosystems.
#
# Usage: jl_bench.jl <algorithm> <op> <bits> <iterations>
#
# Algorithms: rsa, elgamal, rabin, paillier, ss, cocks
# Ops:        keygen, encrypt, decrypt
# Output:     one duration in microseconds per line on stdout, no header.
#             Times the *operation only* — key generation cost is excluded
#             from encrypt/decrypt timings (key is generated once and reused).
#
# Implementation note: Julia 1.12's strict world-age rules forbid calling
# functions defined by `include` from a frame that pre-existed the include.
# So we read ARGS, include the matching module at top level, and only then
# enter the timed section.

length(ARGS) == 4 || (println(stderr, "usage: jl_bench.jl <alg> <op> <bits> <n>"); exit(2))
const ALG  = ARGS[1]
const OP   = ARGS[2]
const BITS = parse(Int, ARGS[3])
const N    = parse(Int, ARGS[4])

using Random
Random.seed!(20260506)

const SRC = joinpath(@__DIR__, "..", "src")

if     ALG == "rsa";      include(joinpath(SRC, "rsa.jl"))
elseif ALG == "elgamal";  include(joinpath(SRC, "elgamal.jl"))
elseif ALG == "rabin";    include(joinpath(SRC, "rabin.jl"))
elseif ALG == "paillier"; include(joinpath(SRC, "paillier.jl"))
elseif ALG == "ss";       include(joinpath(SRC, "ss.jl"))
elseif ALG == "cocks";    include(joinpath(SRC, "cocks.jl"))
else error("unknown algorithm: $ALG")
end

# Per-scheme adapters: extract pub/priv from generateKeys' return tuple.
enc_adapter = Dict(
    "rsa"      => (k, m) -> encrypt(m, k[1], k[3]),
    "elgamal"  => (k, m) -> encrypt(m, k[2]),
    "rabin"    => (k, m) -> encrypt(m, k[1]),
    "paillier" => (k, m) -> encrypt(m, k[2]),
    "ss"       => (k, m) -> encrypt(m, k[1]),
    "cocks"    => (k, m) -> encrypt(m, k[1]),
)
dec_adapter = Dict(
    "rsa"      => (k, c) -> decrypt(c, k[2], k[3]),
    "elgamal"  => (k, c) -> decrypt(c, k[1]),
    "rabin"    => (k, c) -> decrypt(c, k[2]),
    "paillier" => (k, c) -> decrypt(c, k[1]),
    "ss"       => (k, c) -> decrypt(c, k[2]),
    "cocks"    => (k, c) -> decrypt(c, k[2]),
)

if OP == "keygen"
    generateKeys(BITS, false)  # warmup
    for _ in 1:N
        t0 = time_ns()
        generateKeys(BITS, false)
        t1 = time_ns()
        println((t1 - t0) / 1e3)
    end
elseif OP == "encrypt"
    key = generateKeys(BITS, false)
    msg = encode("benchmark")
    enc = enc_adapter[ALG]
    enc(key, msg)  # warmup
    for _ in 1:N
        t0 = time_ns()
        enc(key, msg)
        t1 = time_ns()
        println((t1 - t0) / 1e3)
    end
elseif OP == "decrypt"
    key = generateKeys(BITS, false)
    msg = encode("benchmark")
    enc = enc_adapter[ALG]
    dec = dec_adapter[ALG]
    c   = enc(key, msg)
    dec(key, c)  # warmup
    for _ in 1:N
        t0 = time_ns()
        dec(key, c)
        t1 = time_ns()
        println((t1 - t0) / 1e3)
    end
else
    error("unknown op: $OP")
end
