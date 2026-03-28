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

include("rsa.jl")

function main()
    infile  = stdin
    outfile = stdout
    pubfile = "/tmp/rsa.pub"

    i = 1
    while i <= length(ARGS)
        if ARGS[i] in ["-i", "--infile"] && i + 1 <= length(ARGS)
            infile  = open(ARGS[i + 1], "r"); i += 2
        elseif ARGS[i] in ["-o", "--outfile"] && i + 1 <= length(ARGS)
            outfile = open(ARGS[i + 1], "w"); i += 2
        elseif ARGS[i] in ["-k", "--pubkey"] && i + 1 <= length(ARGS)
            pubfile = ARGS[i + 1]; i += 2
        else
            i += 1
        end
    end

    # Public key: (n, e)
    n = parse(BigInt, readline(open(pubfile)))
    e = parse(BigInt, readlines(open(pubfile))[2])

    block = (ndigits(n, base=2) - 1) ÷ 8
    while !eof(infile)
        bytes = read(infile, block - 1)
        if isempty(bytes) break end
        bytes = vcat([0xFF], bytes)
        m = parse(BigInt, "0x" * bytes2hex(bytes))
        c = encrypt(m, e, n)
        println(outfile, c)
    end

    infile  !== stdin  && close(infile)
    outfile !== stdout && close(outfile)
end

main()
