#!/usr/bin/env julia

# BSD 2-Clause License
#
# Copyright (c) 2022, Darrell Long
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

# Cryptographic random numbers would be ideal, but this is just a simple example.

using Random

#=
Trivial secret splitting: choose two pseudo-random numbers r and s and return those
numbers along with them exclusive or'd with the message.
=#

function splitEncode(s)
    bytes = codeunits(s) # UTF-8 bytes
    b = BigInt(0)
    for (i, c) in enumerate(bytes) # Little-endian integer
        b += BigInt(c) << (8 * (i - 1))
    end
    l = ndigits(b, base=2)
    r = rand(big"2"^l:big"2"^(l + 1))
    t = rand(big"2"^l:big"2"^(l + 1))
    (r, t, r ⊻ t ⊻ b)
end

#=
Decoding in this trivial secret splitting scheme is simply the exclusive or of the three
pseudo-random numbers.
=#

function splitDecode(r, t, u)
    m = r ⊻ t ⊻ u
    nbytes = (ndigits(m, base=2) + 7) ÷ 8
    bytes  = UInt8[(m >> (8 * i)) & 0xFF for i in 0:nbytes-1]
    String(bytes)
end

if abspath(PROGRAM_FILE) == @__FILE__
    try
        print("?? ")
        for m in eachline()
            if m in ["Quit", "quit", "Q", "q", "Exit", "exit"] break end
            (a, b, c) = splitEncode(m)
            println("a = $a")
            println("b = $b")
            println("c = $c")
            println("msg = $(splitDecode(a, b, c))")
            print("?? ")
        end
    catch
        println("\nSo long!")
    end
end
