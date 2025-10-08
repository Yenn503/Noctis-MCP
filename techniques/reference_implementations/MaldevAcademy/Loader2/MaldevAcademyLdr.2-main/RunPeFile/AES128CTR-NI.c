/*
	Refactored From: https://github.com/NUL0x4C/Intel.AES-NI/blob/main/AES-NI/Aes.intrinsic.c
*/

#include <Windows.h>
#include <wmmintrin.h>
#include "Utilities.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static void Aes128KeyExpansion(const unsigned char* pAesKey, __m128i* pKeySchedule)
{
    __m128i xmmTemp1, xmmTemp2;

    // Load master key
    xmmTemp1 = _mm_loadu_si128((const __m128i*)pAesKey);
    pKeySchedule[0] = xmmTemp1;

    // Round 1
    xmmTemp2 = _mm_aeskeygenassist_si128(xmmTemp1, 0x01);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[1] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 2
    xmmTemp2 = _mm_aeskeygenassist_si128(pKeySchedule[1], 0x02);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(pKeySchedule[1], _mm_slli_si128(pKeySchedule[1], 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[2] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 3
    xmmTemp2 = _mm_aeskeygenassist_si128(pKeySchedule[2], 0x04);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(pKeySchedule[2], _mm_slli_si128(pKeySchedule[2], 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[3] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 4
    xmmTemp2 = _mm_aeskeygenassist_si128(pKeySchedule[3], 0x08);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(pKeySchedule[3], _mm_slli_si128(pKeySchedule[3], 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[4] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 5
    xmmTemp2 = _mm_aeskeygenassist_si128(pKeySchedule[4], 0x10);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(pKeySchedule[4], _mm_slli_si128(pKeySchedule[4], 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[5] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 6
    xmmTemp2 = _mm_aeskeygenassist_si128(pKeySchedule[5], 0x20);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(pKeySchedule[5], _mm_slli_si128(pKeySchedule[5], 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[6] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 7
    xmmTemp2 = _mm_aeskeygenassist_si128(pKeySchedule[6], 0x40);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(pKeySchedule[6], _mm_slli_si128(pKeySchedule[6], 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[7] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 8
    xmmTemp2 = _mm_aeskeygenassist_si128(pKeySchedule[7], 0x80);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(pKeySchedule[7], _mm_slli_si128(pKeySchedule[7], 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[8] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 9
    xmmTemp2 = _mm_aeskeygenassist_si128(pKeySchedule[8], 0x1B);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(pKeySchedule[8], _mm_slli_si128(pKeySchedule[8], 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[9] = _mm_xor_si128(xmmTemp1, xmmTemp2);

    // Round 10
    xmmTemp2 = _mm_aeskeygenassist_si128(pKeySchedule[9], 0x36);
    xmmTemp2 = _mm_shuffle_epi32(xmmTemp2, _MM_SHUFFLE(3, 3, 3, 3));
    xmmTemp1 = _mm_xor_si128(pKeySchedule[9], _mm_slli_si128(pKeySchedule[9], 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    xmmTemp1 = _mm_xor_si128(xmmTemp1, _mm_slli_si128(xmmTemp1, 4));
    pKeySchedule[10] = _mm_xor_si128(xmmTemp1, xmmTemp2);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

void Aes128CTRCrypt(IN OUT unsigned char* pBuffer, IN unsigned __int64 uBufferSize, IN unsigned char* pAesKey, IN unsigned char* pAesIv)
{
    __m128i xmmKeySchedule[11];
    Aes128KeyExpansion(pAesKey, xmmKeySchedule);

    __m128i xmmCtr = _mm_loadu_si128((const __m128i*)pAesIv);
    unsigned __int64 uIndex = 0;

    for (; uIndex + 16 <= uBufferSize; uIndex += 16)
    {
        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKeystream = xmmCtr;
        xmmKeystream = _mm_xor_si128(xmmKeystream, xmmKeySchedule[0]);

        for (int iRound = 1; iRound < 10; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);

        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[10]);

        __m128i xmmData = _mm_loadu_si128((const __m128i*)(pBuffer + uIndex));
        xmmData = _mm_xor_si128(xmmData, xmmKeystream);
        _mm_storeu_si128((__m128i*)(pBuffer + uIndex), xmmData);
    }

    if (uIndex < uBufferSize)
    {
        unsigned int uBytesLeft = (unsigned int)(uBufferSize - uIndex);
        unsigned char u8KeystreamBuf[16];

        unsigned int uCtrLow = _mm_extract_epi32(xmmCtr, 3) + 1;
        xmmCtr = _mm_insert_epi32(xmmCtr, uCtrLow, 3);

        __m128i xmmKeystream = xmmCtr;
        xmmKeystream = _mm_xor_si128(xmmKeystream, xmmKeySchedule[0]);

        for (int iRound = 1; iRound < 10; ++iRound)
            xmmKeystream = _mm_aesenc_si128(xmmKeystream, xmmKeySchedule[iRound]);

        xmmKeystream = _mm_aesenclast_si128(xmmKeystream, xmmKeySchedule[10]);
        _mm_storeu_si128((__m128i*)u8KeystreamBuf, xmmKeystream);

        for (unsigned int j = 0; j < uBytesLeft; ++j)
            pBuffer[uIndex + j] ^= u8KeystreamBuf[j];
    }
}
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
