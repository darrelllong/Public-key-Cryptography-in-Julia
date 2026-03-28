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
    bits    = 2048
    pubfile = "/tmp/rsa.pub"
    prvfile = "/tmp/rsa.priv"

    i = 1
    while i <= length(ARGS)
        if ARGS[i] in ["-b", "--bits"] && i + 1 <= length(ARGS)
            bits = parse(Int64, ARGS[i + 1]); i += 2
        elseif ARGS[i] in ["-e", "--pubfile"] && i + 1 <= length(ARGS)
            pubfile = ARGS[i + 1]; i += 2
        elseif ARGS[i] in ["-d", "--privfile"] && i + 1 <= length(ARGS)
            prvfile = ARGS[i + 1]; i += 2
        else
            i += 1
        end
    end

    (e, d, n) = generateKeys(bits)

    open(pubfile, "w") do f
        println(f, n) # Public key: (n, e)
        println(f, e)
    end

    open(prvfile, "w") do f
        println(f, n) # Private key: (n, d)
        println(f, d)
    end

    println("Public key written to $pubfile")
    println("Private key written to $prvfile")
end

main()
