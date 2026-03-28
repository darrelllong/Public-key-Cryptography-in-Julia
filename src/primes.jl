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

using Random

isEven(n) = n & 0x1 == 0

isOdd(n)  = n & 0x1 == 1

#=
Compute log₂(n), returns -1 (invalid) for log₂(0).
=#

function lg(n)
    k = -1
    n = abs(n)
    while n > 0
        n >>= 1
        k  += 1
    end
    k
end

#=
a^d using the method of repeated squares.

Every integer can be written as a sum of powers of 2 including the exponent. By repeated
squaring a is raised to successive powers of 2. Multiplying these partial powers is the
same as adding the exponents.
=#

function power(a, d)
    v = 1 # Value
    p = a # Powers of a
    while d > 0
        if isOdd(d) # 1 bit in the exponent
            v *= p
        end
        p *= p  # Next power of two
        d >>= 1 # Shift exponent one bit
    end
    v
end

#=
a^b (mod n) using the method of repeated squares.

Every integer can be written as a sum of powers of 2 including the exponent. By repeated
squaring a is raised to successive powers of 2. Multiplying these partial powers is the
same as adding the exponents.
=#

function powerMod(a, b, n)
    v = BigInt(1) # Value
    p = BigInt(a) # Powers of a
    while b > 0
        if isOdd(b) # 1 bit in the exponent
            v = (v * p) % n
        end
        p = (p * p) % n # Next power of two
        b >>= 1          # Shift exponent one bit
    end
    v
end

#=
Determine whether n = a^b using binary search, should require O(lg n (lg lg n)^2) time.
=#

function perfectPower(n)
    logN = lg(n)
    for b in 2:logN
        low  = BigInt(2)
        high = BigInt(1) << (logN ÷ b + 1)
        while low < high - 1
            middle = (low + high) ÷ 2
            ab = power(middle, b)
            if ab > n
                high = middle
            elseif ab < n
                low = middle
            else
                return (middle, b)
            end
        end
    end
    (nothing, nothing)
end

isPerfectPower(n) = perfectPower(n) != (nothing, nothing)

#=
Factors n into the form d * 2^r.
=#

function getDR(n)
    d = n
    r = 0
    while isEven(d)
        d >>= 1
        r  += 1
    end
    (d, r)
end

#=
The witness loop of the Miller-Rabin probabilistic primality test.
=#

function witness(a, n)
    (d, r) = getDR(n - 1) # Factor n - 1 into d * 2^r
    x = powerMod(a, d, n)
    for _ in 1:r
        y = powerMod(x, 2, n)
        if y == 1 && x != 1 && x != n - 1
            return true
        end
        x = y
    end
    x != 1
end

#=
Miller-Rabin probabilistic primality test of n with confidence k.
=#

function isPrimeMR(n, k=100)
    if n < 2 || (n != 2 && isEven(n))
        return false
    end
    if n == 2 || n == 3
        return true
    end
    for _ in 1:k
        a = rand(BigInt(2):n - 1) # Euler witness (or liar)
        if witness(a, n)
            return false
        end
    end
    true
end

#=
Compute the Jacobi symbol:
  ⎡  0  if n ≡ 0 (mod k)
  ⎢  1  if n ≢ 0 (mod k) ∧ (∃x) n ≡ x² (mod k)
  ⎣ -1  if n ≢ 0 (mod k) ∧ (∄x) n ≡ x² (mod k)
=#

function Jacobi(n, k)
    @assert k > 0 && isOdd(k)
    n = n % k
    t = 1
    while n != 0
        while isEven(n)
            n ÷= 2
            r  = k % 8
            if r == 3 || r == 5
                t = -t
            end
        end
        n, k = k, n
        if n % 4 == 3 && k % 4 == 3
            t = -t
        end
        n = n % k
    end
    k == 1 ? t : 0
end

#=
Solovay-Strassen probabilistic primality test of n with confidence k.
=#

function isPrimeSS(n, k=100)
    if n < 2 || (n != 2 && isEven(n))
        return false
    end
    if n == 2 || n == 3
        return true
    end
    for _ in 1:k
        a = rand(BigInt(2):n - 1) # Euler witness (or liar)
        x = Jacobi(a, n)
        if x == 0 || powerMod(a, (n - 1) ÷ 2, n) != (n + x) % n
            return false
        end
    end
    true
end

#=
Chooses Selfridge's parameters for the Lucas primality test.
Returns: (D, P, Q)
=#

function chooseSelfridge(n)
    d = 5
    s = 1
    while true
        D = d * s
        if gcd(D, n) == 1 && Jacobi(D, n) == -1 # Guaranteed to occur if n is not a perfect square.
            return (D, 1, (1 - D) ÷ 4)
        end
        d  = d + 2
        s *= -1
    end
end

#=
If x is even, x is halved directly. If x is odd, then n is added to x. n is
assumed to be odd since it is a candidate prime, so the result will be even
and can be halved. This does not change the answer mod n.
=#

function halve(x, n)
    if x % 2 != 0
        x += n
    end
    x ÷ 2
end

#=
Computes the i-th element of the Lucas sequence with parameters p and d,
where q = (1 - d) / 4 (mod n).
=#

function computeUV(i, n, p, d)
    if i == 1
        return (BigInt(1), BigInt(p))
    elseif i % 2 == 0
        (U_k, V_k) = computeUV(i ÷ 2, n, p, d)
        U_2k = U_k * V_k
        V_2k = halve(V_k * V_k + d * U_k * U_k, n)
        return (U_2k % n, V_2k % n)
    else
        (U_2k, V_2k) = computeUV(i - 1, n, p, d)
        U_2k1 = halve(p * U_2k + V_2k, n)
        V_2k1 = halve(d * U_2k + p * V_2k, n)
        return (U_2k1 % n, V_2k1 % n)
    end
end

#=
Checks if an integer is a strong Lucas probable prime.
=#

function isPrimeLS(n)
    if n < 2 || (n != 2 && isEven(n)) || isPerfectPower(n)
        return false
    end
    if n == 2 || n == 3
        return true
    end
    (d, p, q) = chooseSelfridge(n)
    (u, v) = computeUV(n + 1, n, p, d)
    u == 0 && v == mod(2 * q, n)
end

#=
Strong Fermat (Miller-Rabin with fixed base) test with base a = 2.
=#

function isPrimeF(n)
    if n < 2 || (n != 2 && isEven(n))
        return false
    end
    if n == 2 || n == 3
        return true
    end
    !witness(2, n)
end

#=
Runs a Fermat (Miller-Rabin with fixed base) test base 2 and a Lucas-Selfridge test.
It is conjectured that pseudoprimes under both tests are significantly different so
if a number passes both it is very likely to be truly prime.
=#

isPrimeBPSW(n, k=100) = isPrimeF(n) && isPrimeLS(n)

# Default is to use Miller-Rabin.

isPrime(n, k=100) = isPrimeMR(n, k)

# Routines to generate primes

#=
Generate and return a random prime in the range [low, high].
=#

function randomPrime(low, high, confidence=100)
    guess = BigInt(0) # Certainly not prime!
    while isEven(guess) || !isPrime(guess, confidence)
        guess = rand(low:high) # Half will be even, the rest have Pr[prime] ≈ 1/log(N).
    end
    guess
end

#=
Generate and return a safe prime in the range [low, high].

A safe prime follows a Sophie Germain prime. If prime(p) and prime(2p + 1) then p is a
Sophie Germain prime and 2p + 1 is a safe prime.
=#

function safePrime(low, high, confidence=100)
    p = randomPrime(low, high)
    while !isPrime(2 * p + 1, confidence)
        p = randomPrime(low, high)
    end
    2 * p + 1
end

#=
Generate a Rabin prime p ≡ 3 (mod 4), low ≤ p ≤ high. Default is to use a safe prime.
=#

function rabinPrime(low, high, safe=true)
    f = safe ? safePrime : randomPrime
    p = f(low, high)
    while p % 4 != 3
        p = f(low, high)
    end
    p
end

#=
The extended Euclidean algorithm computes the greatest common divisor and the Bézout
coefficients s, t.

Returns (remainder, (s, t))
=#

function extendedGCD(a, b)
    r,  rP = BigInt(a), BigInt(b)
    s,  sP = BigInt(1), BigInt(0)
    t,  tP = BigInt(0), BigInt(1)
    while rP != 0
        q  = r ÷ rP
        r,  rP = rP,  r  - q * rP
        s,  sP = sP,  s  - q * sP
        t,  tP = tP,  t  - q * tP
    end
    (r, (s, t))
end

#=
Compute the greatest common divisor gcd(a, b) using the Euclidean algorithm.
=#

function gcd(a, b)
    while b != 0
        a, b = b, a % b # The simple version so students see what is happening.
    end
    abs(a)
end

#=
Compute the least common multiple lcm(a, b).
=#

function lcm(a, b)
    if a == 0 || b == 0
        error("lcm is not defined for 0")
    end
    abs(a * b) ÷ gcd(a, b)
end

#=
Compute the multiplicative inverse of a (mod n) using the Euclidean algorithm and Bézout's
identity: a×s + b×t = 1.
=#

function inverse(a, n)
    (r, (s, t)) = extendedGCD(a, n) # We did the hard part already.
    if r > 1
        return nothing
    end
    s < 0 ? s + n : s
end

#=
Creates a generator in the neighborhood of n for the group defined by p.

A generator must not be congruent to 1 for any of its powers that are proper divisors
of p – 1.  Since p is safe prime, there are only two: 2 and (p – 1) / 2. The number of
such generators is 𝜑(p – 1).
=#

function groupGenerator(n, p)
    g = BigInt(n)
    q = (p - 1) ÷ 2
    while powerMod(g, 2, p) == 1 || powerMod(g, q, p) == 1
        g += 1
    end
    g
end

function encode(s)
    tot = BigInt(0)
    mlt = BigInt(1)
    for c in s
        tot += mlt * BigInt(c)
        mlt *= 256
    end
    tot
end

function decode(n)
    chars = Char[]
    while n > 0
        push!(chars, Char(n % 256))
        n ÷= 256
    end
    String(chars)
end

# Interactive test

if abspath(PROGRAM_FILE) == @__FILE__
    using Dates

    g = encode("Try harder!")
    try
        while g != 0
            print("?? ")
            g = parse(BigInt, readline())
            t0 = now()
            mr   = isPrimeMR(g)
            t1 = now()
            ss   = isPrimeSS(g)
            t2 = now()
            bpsw = isPrimeBPSW(g)
            t3 = now()
            if g == 2 || (isOdd(g) && mr && ss && bpsw)
                println("$g is probably prime.")
            else
                println("$g is composite.")
                if mr   println("Miller-Rabin disagrees")   end
                if ss   println("Solovay-Strassen disagrees") end
                if bpsw println("BPSW disagrees")           end
            end
            (a, b) = perfectPower(g)
            if (a, b) != (nothing, nothing)
                println("$g = $a^$b is a perfect power.")
            end
            println("Performance:")
            println("\tMiller-Rabin:      $(t1 - t0)")
            println("\tSolovay-Strassen:  $(t2 - t1)")
            println("\tBPSW:              $(t3 - t2)")
        end
    catch e
        println("\nSo long!")
    end
end
