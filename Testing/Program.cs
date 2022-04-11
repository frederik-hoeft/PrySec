//#define custom

using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Core.Simd;
using PrySec.Security.Cryptography.Hashing.Blake2;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using Testing;

A.Asdf();

static class A
{
    private static readonly int[,] SIGMA_IV = new int[12, 16]
    {
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 11, 12, 13, 14, 15
        },
        {
            14, 10, 4, 8, 9, 15, 13, 6,
            1, 12, 0, 2, 11, 7, 5, 3
        },
        {
            11, 8, 12, 0, 5, 2, 15, 13,
            10, 14, 3, 6, 7, 1, 9, 4
        },
        {
            7, 9, 3, 1, 13, 12, 11, 14,
            2, 6, 5, 10, 4, 0, 15, 8
        },
        {
            9, 0, 5, 7, 2, 4, 10, 15,
            14, 1, 11, 12, 6, 8, 3, 13
        },
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };

    public static void Asdf()
    {
        Vector256<ulong> m0 = Vector256.Create(0ul, 1ul, 2ul, 3ul);
        Vector256<ulong> m1 = Vector256.Create(4ul, 5ul, 6ul, 7ul);
        Vector256<ulong> m2 = Vector256.Create(8ul, 9ul, 10ul, 11ul);
        Vector256<ulong> m3 = Vector256.Create(12ul, 13ul, 14ul, 15ul);

        Assert(LoadMessage01(in m0, in m1, in m2, in m3), 0, 2, 4, 6);
        Assert(LoadMessage02(in m0, in m1, in m2, in m3), 1, 3, 5, 7);
        Assert(LoadMessage03(in m0, in m1, in m2, in m3), 8, 10, 12, 14);
        Assert(LoadMessage04(in m0, in m1, in m2, in m3), 9, 11, 13, 15);

        Assert(LoadMessage11(in m0, in m1, in m2, in m3), 14, 4, 9, 13);
        Assert(LoadMessage12(in m0, in m1, in m2, in m3), 10, 8, 15, 6);
        Assert(LoadMessage13(in m0, in m1, in m2, in m3), 1, 0, 11, 5);
        Assert(LoadMessage14(in m0, in m1, in m2, in m3), 12, 2, 7, 3);
    }

    static Vector256<ulong> LoadMessage01(in Vector256<ulong> m0, in Vector256<ulong> m1, in Vector256<ulong> m2, in Vector256<ulong> m3)
    {
        return AvxPrimitives.SwapMiddleX64(Avx2.UnpackLow(m0, m1));
    }

    static Vector256<ulong> LoadMessage02(in Vector256<ulong> m0, in Vector256<ulong> m1, in Vector256<ulong> m2, in Vector256<ulong> m3)
    {
        return AvxPrimitives.SwapMiddleX64(Avx2.UnpackHigh(m0, m1));
    }

    static Vector256<ulong> LoadMessage03(in Vector256<ulong> m0, in Vector256<ulong> m1, in Vector256<ulong> m2, in Vector256<ulong> m3)
    {
        return AvxPrimitives.SwapMiddleX64(Avx2.UnpackLow(m2, m3));
    }

    static Vector256<ulong> LoadMessage04(in Vector256<ulong> m0, in Vector256<ulong> m1, in Vector256<ulong> m2, in Vector256<ulong> m3)
    {
        return AvxPrimitives.SwapMiddleX64(Avx2.UnpackHigh(m2, m3));
    }

    static Vector256<ulong> LoadMessage11(in Vector256<ulong> m0, in Vector256<ulong> m1, in Vector256<ulong> m2, in Vector256<ulong> m3) => 
        Vector256.Create(Sse2.UnpackLow(m3.GetUpper(), m1.GetLower()), Sse2.UnpackHigh(m2.GetLower(), m3.GetLower()));

    static Vector256<ulong> LoadMessage12(in Vector256<ulong> m0, in Vector256<ulong> m1, in Vector256<ulong> m2, in Vector256<ulong> m3)
    {
        //b0 = _mm_unpacklo_epi64(m5, m4); \
        //b1 = _mm_alignr_epi8(m3, m7, 8); \
        return Vector256.Create(Sse2.UnpackLow(m2.GetUpper(), m2.GetLower()), Ssse3.AlignRight(m1.GetUpper(), m3.GetUpper(), 8));
    }

    static Vector256<ulong> LoadMessage13(in Vector256<ulong> m0, in Vector256<ulong> m1, in Vector256<ulong> m2, in Vector256<ulong> m3)
    {
        return Vector256.Create(Avx2.Permute4x64(m0, 0b10110001).GetLower(), Sse2.UnpackHigh(m2.GetUpper(), m1.GetLower()));
    }

    static Vector256<ulong> LoadMessage14(in Vector256<ulong> m0, in Vector256<ulong> m1, in Vector256<ulong> m2, in Vector256<ulong> m3)
    {
        return Vector256.Create(Sse2.UnpackLow(m3.GetLower(), m0.GetUpper()), Avx.Blend(m0.AsDouble(), Avx2.Permute4x64(m1, 0b10110001).AsDouble(), 0x4).AsUInt64().GetUpper());
    }

    static int i = 0;

    static void Assert(Vector256<ulong> v, ulong v1, ulong v2, ulong v3, ulong v4)
    {
        if (v.GetElement(0) != v1 || v.GetElement(1) != v2 || v.GetElement(2) != v3 || v.GetElement(3) != v4)
        {
            Console.WriteLine($"{i} threw assertion: Got {v}. Expected <{v1}, {v2}, {v3}, {v4}>");
        }
        else
        {
            Console.WriteLine($"{i} passed.");
        }
        i++;
    }
}
#if false
const uint WARMUP = 10_000;
const uint ITERATIONS = 250_000;

unsafe
{
    string str = new('A', 100000);
    int strLength = str.Length;
    DeterministicSpan<byte> span = DeterministicSpan<byte>.Allocate(strLength);
    fixed (char* pStr = str)
    {
        Unsafe.CopyBlockUnaligned(span.BasePointer, pStr, (uint)strLength);
        Console.WriteLine($"Calling Test Methods {ITERATIONS} times with additional warmup of {WARMUP} ...");
        Console.WriteLine();
        // setup

        // warmup
        Blake2b b = new Blake2b();
        for (uint i = 0; i < WARMUP; i++)
        {
            using var _ = b.ComputeHash<byte, DeterministicSpan<byte>, DeterministicSpan<byte>>(ref span);
        }
        Stopwatch stopwatch = new();
        stopwatch.Start();
        for (uint i = 0; i < ITERATIONS; i++)
        {
            using var _ = b.ComputeHash<byte, DeterministicSpan<byte>, DeterministicSpan<byte>>(ref span);
        }
        stopwatch.Stop();
        Console.WriteLine(stopwatch.Elapsed);
        Console.WriteLine($"That's {stopwatch.ElapsedMilliseconds / (double)ITERATIONS} ms / it");
        Console.WriteLine($"Or {(double)ITERATIONS / stopwatch.ElapsedMilliseconds * 1000} it / s");
        Console.WriteLine();
    }
}

/*
 * 
 * 
pmdbs2x blake:

00:xx:xx
That's 0.214306 ms / hash
Or 4666.2249307065595 hashes / s

PrySec AVX2
00:00:45.2073221
That's 0.180828 ms / it
Or 5530.117017276085 it / s

Prysec default
00:01:06.7934403
That's 0.267172 ms / it
Or 3742.9071908732953 it / s

=======================================

Timing SHA2:

00:03:47.6726719
That's 0.0910688 ms / hash
Or 10980.709090270213 hashes / s

------------------------------------------------

BUILT-IN Timing:

00:02:04.2549446
That's 0.0497016 ms / hash
Or 20120.076617251758 hashes / s

------------------------------------------------

pmdbs2XNative Timing:

00:00:35.2724371
That's 0.00141088 ms / hash
Or 708777.500567022 hashes / s

======================================

SHA-1

unoptimized custom:

00:00:14.7704745
That's 0.0005908 ms / hash
Or 1692620.1760324985 hashes / s

using seperate variables:

00:00:14.3765852
That's 0.00057504 ms / hash
Or 1739009.4602114637 hashes / s

-------------------------------------------

BUILT-IN Timing:

00:00:05.9739521
That's 0.00023892 ms / hash
Or 4185501.423070484 hashes / s
 */
#endif