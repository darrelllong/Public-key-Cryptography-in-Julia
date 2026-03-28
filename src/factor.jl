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
Pollard's ρ (rho) algorithm for integer factorization.
Useful for medium-sized composites, but not for sizes used in public-key cryptography.
=#

rhodef(x, b, n) = (b + x + x * x) % n

#=
Compute Pollard's ρ to find a nontrivial factor of n.
Reinitialize parameters and retry if the computed factor equals n.
=#

function rho(n)
    factor = n # Initialize with the trivial factor
    while factor == n
        b    = rand(BigInt(1):max(BigInt(2), n - 2))
        s    = rand(BigInt(0):max(BigInt(2), n))
        slow = s  # Tortoise
        fast = s  # Hare
        factor = BigInt(1) # Reset factor for this trial

        while factor == 1
            slow   = rhodef(slow, b, n)
            fast   = rhodef(rhodef(fast, b, n), b, n)
            factor = gcd(slow - fast, n)
        end
    end
    factor
end

function factor(n)
    if n == 1 || isPrime(n)
        return [n]
    else
        f = BigInt[]
        q = [n]
        while !isempty(q)
            x = pop!(q)
            r = rho(x)
            y = x ÷ r
            if isPrime(r)
                push!(f, r)
            elseif r > 1
                push!(q, r)
            end
            if isPrime(y)
                push!(f, y)
            elseif y > 1
                push!(q, y)
            end
        end
        return f
    end
end

if abspath(PROGRAM_FILE) == @__FILE__
    n = BigInt(1)
    try
        while n != 0
            print("?? ")
            n = parse(BigInt, readline())
            f = factor(n)
            sort!(f)
            product = reduce(*, f)
            println("$n = $f = $product")
        end
    catch
        println("\nBye!")
    end
end
