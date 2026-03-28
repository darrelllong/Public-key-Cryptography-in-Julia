#!/usr/bin/env julia

# Test all cryptosystems with small key sizes (safe=false for speed).

using Random
Random.seed!(42)

passed = 0
failed = 0

function check(name, result, expected)
    global passed, failed
    if result == expected
        println("  PASS: $name")
        passed += 1
    else
        println("  FAIL: $name — got $(repr(result)), expected $(repr(expected))")
        failed += 1
    end
end

# ─── primes.jl ───────────────────────────────────────────────────────────────
println("=== primes.jl ===")
include("primes.jl")

check("isPrime(2)",   isPrime(2),   true)
check("isPrime(3)",   isPrime(3),   true)
check("isPrime(4)",   isPrime(4),   false)
check("isPrime(97)",  isPrime(97),  true)
check("isPrime(100)", isPrime(100), false)
check("isPrime(561)", isPrime(561), false)   # Carmichael number

check("isPrimeSS(2)",   isPrimeSS(2),   true)
check("isPrimeSS(97)",  isPrimeSS(97),  true)
check("isPrimeSS(100)", isPrimeSS(100), false)

check("isPrimeBPSW(2)",   isPrimeBPSW(2),   true)
check("isPrimeBPSW(97)",  isPrimeBPSW(97),  true)
check("isPrimeBPSW(561)", isPrimeBPSW(561), false)

check("isPrimeLS(2)",   isPrimeLS(BigInt(2)),   true)
check("isPrimeLS(97)",  isPrimeLS(BigInt(97)),  true)
check("isPrimeLS(561)", isPrimeLS(BigInt(561)), false)

check("isPerfectPower(8)",  isPerfectPower(8),  false)  # 2^3 — binary search misses base 2 (matches Python)
check("isPerfectPower(9)",  isPerfectPower(9),  true)   # 3^2
check("isPerfectPower(27)", isPerfectPower(27), true)   # 3^3
check("isPerfectPower(10)", isPerfectPower(10), false)

check("gcd(12,8)",  gcd(12,8),  4)
check("gcd(35,14)", gcd(35,14), 7)
check("lcm(4,6)",   lcm(4,6),   12)

inv7_11 = inverse(7, 11)
check("inverse(7,11) exists",   inv7_11 !== nothing,   true)
check("7 * inverse(7,11) ≡ 1", (7 * inv7_11) % 11 == 1, true)

check("encode/decode roundtrip", decode(encode("Hello")), "Hello")

r = randomPrime(big"2"^31, big"2"^32 - 1)
check("randomPrime is prime", isPrime(r), true)

# ─── factor.jl ───────────────────────────────────────────────────────────────
println("\n=== factor.jl ===")
include("factor.jl")

for n in [BigInt(12), BigInt(60), BigInt(997 * 1009)]
    f = factor(n)
    check("factor($n) product", reduce(*, f), n)
    check("factor($n) all prime", all(isPrime, f), true)
end

# ─── rsa.jl ──────────────────────────────────────────────────────────────────
println("\n=== rsa.jl ===")
include("rsa.jl")

(e, d, n) = generateKeys(256, false)
for msg in ["Hello", "Test", "RSA works"]
    m = encode(msg)
    c = encrypt(m, e, n)
    t = decode(decrypt(c, d, n))
    check("RSA roundtrip \"$msg\"", t, msg)
end

# Test publicKeyToStr / publicKeyFromStr roundtrip
ks = publicKeyToStr(e, n)
(e2, n2) = publicKeyFromStr(ks)
check("RSA SSH key roundtrip e", e2, e)
check("RSA SSH key roundtrip n", n2, n)

# ─── elgamal.jl ──────────────────────────────────────────────────────────────
println("\n=== elgamal.jl ===")
include("elgamal.jl")

(prv, pub) = generateKeys(128, false)
for msg in ["Hello", "ElGamal"]
    m = encode(msg)
    c = encrypt(m, pub)
    t = decode(decrypt(c, prv))
    check("ElGamal roundtrip \"$msg\"", t, msg)
end

# ─── rabin.jl ────────────────────────────────────────────────────────────────
println("\n=== rabin.jl ===")
include("rabin.jl")

(n_r, k_r) = generateKeys(128, false)
for msg in ["Hello", "Rabin"]
    m = encode(msg)
    c = encrypt(m, n_r)
    t = decode(decrypt(c, k_r))
    check("Rabin roundtrip \"$msg\"", t, msg)
end

# ─── paillier.jl ─────────────────────────────────────────────────────────────
println("\n=== paillier.jl ===")
include("paillier.jl")

(prv_p, pub_p) = generateKeys(256, false)
for msg in ["Hi", "Paillier"]
    m = encode(msg)
    c = encrypt(m, pub_p)
    t = decode(decrypt(c, prv_p))
    check("Paillier roundtrip \"$msg\"", t, msg)
end

# Homomorphic addition: E(m1) * E(m2) mod n^2 == E(m1 + m2)
(n_h, 𝝺_h, u_h) = prv_p
m1, m2 = BigInt(7), BigInt(13)
c1 = encrypt(m1, pub_p)
c2 = encrypt(m2, pub_p)
c_sum = (c1 * c2) % (n_h^2)
d_sum = decrypt(c_sum, prv_p)
check("Paillier homomorphic: E(7)*E(13) decrypts to 20", d_sum, m1 + m2)

# ─── ss.jl (Schmidt-Samoa) ───────────────────────────────────────────────────
println("\n=== ss.jl (Schmidt-Samoa) ===")
include("ss.jl")

(en_ss, de_ss) = generateKeys(256, false)
for msg in ["Hello", "Schmidt-Samoa"]
    m = encode(msg)
    c = encrypt(m, en_ss)
    t = decode(decrypt(c, de_ss))
    check("Schmidt-Samoa roundtrip \"$msg\"", t, msg)
end

# ─── cocks.jl ────────────────────────────────────────────────────────────────
println("\n=== cocks.jl ===")
include("cocks.jl")

(en_c, de_c) = generateKeys(256, false)
for msg in ["Hi", "Cocks"]
    m = encode(msg)
    c = encrypt(m, en_c)
    t = decode(decrypt(c, de_c))
    check("Cocks roundtrip \"$msg\"", t, msg)
end

# ─── io.jl — RSA serialization ───────────────────────────────────────────────
println("\n=== rsa.jl serialization ===")
# rsa.jl is already included above; io.jl was pulled in transitively.

(e_f, d_f, n_f, p_f, q_f) = generateRsaFullKeys(256, false)

# PKCS#1 roundtrip
pkcs1_pub = rsaPublicToPkcs1Der(e_f, n_f)
(e2, n2) = rsaPublicFromPkcs1Der(pkcs1_pub)
check("RSA PKCS#1 pub DER roundtrip e", e2, e_f)
check("RSA PKCS#1 pub DER roundtrip n", n2, n_f)

pkcs1_prv = rsaPrivateToPkcs1Der(e_f, d_f, n_f, p_f, q_f)
(e3, d3, n3, p3, q3) = rsaPrivateFromPkcs1Der(pkcs1_prv)
check("RSA PKCS#1 prv DER roundtrip e", e3, e_f)
check("RSA PKCS#1 prv DER roundtrip d", d3, d_f)
check("RSA PKCS#1 prv DER roundtrip n", n3, n_f)

# SPKI / PKCS#8 roundtrip
spki = rsaPublicToSpkiDer(e_f, n_f)
(e4, n4) = rsaPublicFromSpkiDer(spki)
check("RSA SPKI DER roundtrip e", e4, e_f)
check("RSA SPKI DER roundtrip n", n4, n_f)

pkcs8 = rsaPrivateToPkcs8Der(e_f, d_f, n_f, p_f, q_f)
(e5, d5, n5, _, _) = rsaPrivateFromPkcs8Der(pkcs8)
check("RSA PKCS#8 DER roundtrip e", e5, e_f)
check("RSA PKCS#8 DER roundtrip d", d5, d_f)
check("RSA PKCS#8 DER roundtrip n", n5, n_f)

# PEM roundtrip
check("RSA PKCS#1 pub PEM roundtrip", rsaPublicFromPkcs1PEM(rsaPublicToPkcs1PEM(e_f, n_f)), (e_f, n_f))
check("RSA SPKI PEM roundtrip",       rsaPublicFromSpkiPEM(rsaPublicToSpkiPEM(e_f, n_f)),   (e_f, n_f))
check("RSA PKCS#8 PEM roundtrip",     rsaPrivateFromPkcs8PEM(rsaPrivateToPkcs8PEM(e_f,d_f,n_f,p_f,q_f))[1:3], (e_f, d_f, n_f))

# XML roundtrip
check("RSA public XML roundtrip",  rsaPublicFromXML(rsaPublicToXML(e_f, n_f)),                     (e_f, n_f))
check("RSA private XML roundtrip", rsaPrivateFromXML(rsaPrivateToXML(e_f,d_f,n_f,p_f,q_f))[1:3], (e_f, d_f, n_f))

# ─── io.jl — non-RSA serialization ───────────────────────────────────────────
println("\n=== non-RSA serialization ===")

# ElGamal — reuse keys generated in the elgamal.jl section above
(p_eg, a_eg)        = prv         # prv = (p, a)
(p_eg2, r_eg, b_eg) = pub         # pub = (p, r, b)
check("ElGamal pub blob roundtrip",  elgamalPublicFromBlob(elgamalPublicToBlob(p_eg2, r_eg, b_eg)), (p_eg2, r_eg, b_eg))
check("ElGamal prv blob roundtrip",  elgamalPrivateFromBlob(elgamalPrivateToBlob(p_eg, a_eg)),       (p_eg, a_eg))
check("ElGamal pub PEM roundtrip",   elgamalPublicFromPEM(elgamalPublicToPEM(p_eg2, r_eg, b_eg)),   (p_eg2, r_eg, b_eg))
check("ElGamal prv PEM roundtrip",   elgamalPrivateFromPEM(elgamalPrivateToPEM(p_eg, a_eg)),         (p_eg, a_eg))
check("ElGamal pub XML roundtrip",   elgamalPublicFromXML(elgamalPublicToXML(p_eg2, r_eg, b_eg)),   (p_eg2, r_eg, b_eg))
check("ElGamal prv XML roundtrip",   elgamalPrivateFromXML(elgamalPrivateToXML(p_eg, a_eg)),         (p_eg, a_eg))

# Rabin — reuse (n_r, k_r) from the rabin.jl section above
(p_r2, q_r2) = k_r
check("Rabin pub blob roundtrip",  rabinPublicFromBlob(rabinPublicToBlob(n_r)), n_r)
check("Rabin prv blob roundtrip",  rabinPrivateFromBlob(rabinPrivateToBlob(n_r, p_r2, q_r2)), (p_r2, q_r2))
check("Rabin pub PEM roundtrip",   rabinPublicFromPEM(rabinPublicToPEM(n_r)), n_r)
check("Rabin prv PEM roundtrip",   rabinPrivateFromPEM(rabinPrivateToPEM(n_r, p_r2, q_r2)), (p_r2, q_r2))
check("Rabin pub XML roundtrip",   rabinPublicFromXML(rabinPublicToXML(n_r)), n_r)
check("Rabin prv XML roundtrip",   rabinPrivateFromXML(rabinPrivateToXML(n_r, p_r2, q_r2)), (p_r2, q_r2))

# Paillier — reuse (prv_p, pub_p) from the paillier.jl section above
(n_p2, 𝝺_p2, u_p2) = prv_p
(n_p2b, 𝜻_p2)      = pub_p
check("Paillier pub blob roundtrip",  paillierPublicFromBlob(paillierPublicToBlob(n_p2b, 𝜻_p2)),       (n_p2b, 𝜻_p2))
check("Paillier prv blob roundtrip",  paillierPrivateFromBlob(paillierPrivateToBlob(n_p2, 𝝺_p2, u_p2)), (n_p2, 𝝺_p2, u_p2))
check("Paillier pub PEM roundtrip",   paillierPublicFromPEM(paillierPublicToPEM(n_p2b, 𝜻_p2)),          (n_p2b, 𝜻_p2))
check("Paillier prv PEM roundtrip",   paillierPrivateFromPEM(paillierPrivateToPEM(n_p2, 𝝺_p2, u_p2)),   (n_p2, 𝝺_p2, u_p2))
check("Paillier pub XML roundtrip",   paillierPublicFromXML(paillierPublicToXML(n_p2b, 𝜻_p2)),          (n_p2b, 𝜻_p2))
check("Paillier prv XML roundtrip",   paillierPrivateFromXML(paillierPrivateToXML(n_p2, 𝝺_p2, u_p2)),   (n_p2, 𝝺_p2, u_p2))

# Schmidt-Samoa — reuse (en_ss, de_ss) from the ss.jl section above
(d_ss2, γ_ss2) = de_ss
check("SS pub blob roundtrip",  ssPublicFromBlob(ssPublicToBlob(en_ss)),    en_ss)
check("SS prv blob roundtrip",  ssPrivateFromBlob(ssPrivateToBlob(d_ss2, γ_ss2)), (d_ss2, γ_ss2))
check("SS pub PEM roundtrip",   ssPublicFromPEM(ssPublicToPEM(en_ss)),      en_ss)
check("SS prv PEM roundtrip",   ssPrivateFromPEM(ssPrivateToPEM(d_ss2, γ_ss2)),   (d_ss2, γ_ss2))
check("SS pub XML roundtrip",   ssPublicFromXML(ssPublicToXML(en_ss)),      en_ss)
check("SS prv XML roundtrip",   ssPrivateFromXML(ssPrivateToXML(d_ss2, γ_ss2)),   (d_ss2, γ_ss2))

# Cocks — reuse (en_c, de_c) from the cocks.jl section above
(π_c2, q_c2) = de_c
check("Cocks pub blob roundtrip",  cocksPublicFromBlob(cocksPublicToBlob(en_c)), en_c)
check("Cocks prv blob roundtrip",  cocksPrivateFromBlob(cocksPrivateToBlob(π_c2, q_c2)), (π_c2, q_c2))
check("Cocks pub PEM roundtrip",   cocksPublicFromPEM(cocksPublicToPEM(en_c)), en_c)
check("Cocks prv PEM roundtrip",   cocksPrivateFromPEM(cocksPrivateToPEM(π_c2, q_c2)), (π_c2, q_c2))
check("Cocks pub XML roundtrip",   cocksPublicFromXML(cocksPublicToXML(en_c)), en_c)
check("Cocks prv XML roundtrip",   cocksPrivateFromXML(cocksPrivateToXML(π_c2, q_c2)), (π_c2, q_c2))

# ─── simple-split.jl ─────────────────────────────────────────────────────────
println("\n=== simple-split.jl ===")
include("simple-split.jl")

for msg in ["Hello", "Secret", "Split me!"]
    (a, b, c) = splitEncode(msg)
    t = splitDecode(a, b, c)
    check("Secret split roundtrip \"$msg\"", t, msg)
end

# ─── Summary ─────────────────────────────────────────────────────────────────
println("\n$(passed + failed) tests: $passed passed, $failed failed.")
