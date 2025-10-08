#pragma once
#ifndef REED_SOLOMON_H_
#define REED_SOLOMON_H_

#include <Windows.h>


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Constants
#define RS_FIELD_SIZE              256
#define RS_FIELD_CHARAC            255      // 2^8 - 1
#define RS_PRIM_POLY               0x11D
#define RS_GENERATOR               2
#define RS_FCR                     0 


#define MARKER_LEN                 32
#define LEVEL_PILOT                1
#define LEVEL_DATA                 2
#define QSTEP_PILOT                24.0f
#define QSTEP_DATA                 14.0f
#define REP_HEADER                 9
#define REP_META                   3
#define HEADER_DUP_AT_L2           1

#define FORMAT_VERSION             1
#define HEADER_BYTES_LEN           22
#define HEADER_BITS_LEN            (HEADER_BYTES_LEN * 8)

#define HEADER_PILOT_BITS_LEN      (MARKER_LEN + HEADER_BITS_LEN * REP_HEADER)



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Structures 

typedef struct _RS_CONTEXT {
    DWORD   dwNsym;         // Number of ECC symbols
    DWORD   dwFcr;          // First consecutive root
    DWORD   dwGenerator;    // Generator value
    DWORD   dwPrim;         // Primitive polynomial
} RS_CONTEXT, * PRS_CONTEXT;


typedef struct _RS_BERLEKAMP_CONTEXT {
    BYTE    bSyndromes[RS_FIELD_SIZE];          // Input syndromes
    BYTE    bErrorLocator[RS_FIELD_SIZE];       // Output error locator polynomial
    BYTE    bOldLocator[RS_FIELD_SIZE];         // Previous locator for updates
    BYTE    bTempPoly[RS_FIELD_SIZE];           // Temporary polynomial for calculations
    DWORD   dwSyndromeCount;                    // Number of syndromes (nsym)
    DWORD   dwErrorCount;                       // Number of errors found (L)
    DWORD   dwLocatorLength;                    // Length of error locator polynomial
} RS_BERLEKAMP_CONTEXT, * PRS_BERLEKAMP_CONTEXT;


#pragma pack(push, 1)
typedef struct _STEG_HEADER {
    BYTE    bVersion;                    // Format version number
    BYTE    bRepetitionMeta;             // Repetition factor for metadata encoding
    BYTE    bEccSymbolCount;             // Number of Reed-Solomon ECC symbols
    BYTE    bLevelData;                  // DWT decomposition level for data
    FLOAT   fQuantizationStepData;       // QIM quantization step size for data
    DWORD   dwMetaLengthBits;            // Length of metadata in bits
    DWORD   dwDataLengthBits;            // Length of payload data in bits
    DWORD   dwDataCrc32;                 // CRC32 checksum of compressed payload
    WORD    wHeaderCrc16;                // CRC16 checksum of this header   
} STEG_HEADER, * PSTEG_HEADER;
#pragma pack(pop)

typedef struct _DWT_COEFFS {
    float* pfApproximationCoeffs;        // Low-low frequency coefficients (LL)
    float* pfHorizontalCoeffs;           // High-low frequency coefficients (HL)
    float* pfVerticalCoeffs;             // Low-high frequency coefficients (LH)
    float* pfDiagonalCoeffs;             // High-high frequency coefficients (HH)
    DWORD  dwCoefficientCount;           // Number of coefficients per band
} DWT_COEFFS, * PDWT_COEFFS;


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Functions 

BOOL WINAPI RsCreateContext(
    OUT PRS_CONTEXT pContext,
    IN  DWORD       dwNsym,
    IN  DWORD       dwFcr,
    IN  DWORD       dwGenerator,
    IN  DWORD       dwPrim
);

BOOL WINAPI RsDecodeMessage(
    IN      PRS_CONTEXT pContext,
    IN      PBYTE       pbMsgIn,
    IN      DWORD       dwMsgLen,
    OUT     PBYTE       pbMsgOut,
    OUT     PBYTE       pbEcc,
    IN OUT  PDWORD      pdwErasePos,
    IN      DWORD       dwEraseCount,
    OUT     PDWORD      pdwErrorPos,
    OUT     PDWORD      pdwErrorCount
);



#endif // !REED_SOLOMON_H_
