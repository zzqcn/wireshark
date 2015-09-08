/**
 * @file
 * @brief CAM特征.
 * @author Zhao Ziqing <psyc209@163.com> 
 * @date 2015.09.07
 * @version 0.1
 */

#ifndef __CAMRULE_H__
#define __CAMRULE_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#ifndef __GNUC__
#define inline __inline
#endif

#define MATCH_MODE_MAX  4
enum MatchMode { MM_NULL=0, MM_SHIFT=1, MM_FIXED=2, MM_ANCHOR=4 };
extern const char* str_matchmode[5];

#define PTN_TYPE_MAX    2
enum PtnType { PT_NULL=0, PT_ASCII=1, PT_HEX };
extern const char* str_ptntype[3];

#define ANCHOR_TYPE_MAX 8
enum AnchorType
{
    AT_HTTP_MN=0, AT_USER_AGENT, AT_CONTENT_TYPE, AT_HTTP,
    AT_HOST, AT_X_ONLINE_HOST, AT_0D0A0D0A, AT_REFERER,
    AT_NULL
};
extern const char* str_anchortype[9];

#define SPEC_PTN_MAX    4
enum SpecPtn { SP_NULL=0, SP_GET, SP_POST, SP_HTTP_ACK, SP_WAP_ACK };
extern const char* str_specptn[5];



#define CAMRULE_PRI_MAX     7
#define CAMRULE_LOWPRI_MAX  7


// 特征各项在一行中的索引
#define     CRI_INVALID         -1
#define     CRI_COUNT           32
#define     CRI_MIN             0
#define     CRI_MAX             31

#define     CRI_OPT_NAME        0
#define     CRI_PTN_ID          1
#define     CRI_PTN_NAME        2
#define     CRI_SVC_ID          3
#define     CRI_TABLE_SEL       4
#define     CRI_PTN_PRI         5
#define     CRI_IS_CHECK_TCP    6
#define     CRI_IS_CHECK_UDP    7
#define     CRI_IS_CHECK_PORT   8
#define     CRI_PTN_LOW_PRI     9
#define     CRI_UNKNOWN         10
#define     CRI_UNKNOWN2        11
#define     CRI_PTN_TYPE        12
#define     CRI_PTN_STR         13
#define     CRI_STR_MASK0       14
#define     CRI_STR_MASK1       15
#define     CRI_STR_MASK2       16
#define     CRI_STR_MASK3       17
#define     CRI_STR_MASK4       18
#define     CRI_STR_MASK5       19
#define     CRI_STR_MASK6       20
#define     CRI_STR_MASK7       21
#define     CRI_STR_MATCH_MODE  22
#define     CRI_IS_AFTER_ANCHOR 23
#define     CRI_IS_CHK_CAPITAL  24
#define     CRI_BLOCK_POS       25
#define     CRI_BYTE_POS        26
#define     CRI_ANCHOR_ID       27
#define     CRI_SPEC_PTN_ID     28
#define     CRI_PAYLOAD_LEN     29
#define     CRI_CAM_IDX         30
#define     CRI_IS_AVOID_ERASED 31



int get_maskstr_from_ptnstr(const char* ptnStr,
                             char* maskStr[8],
                             int type,
                             int chkCapital);


#define CAM_INVALID_BYTEPOS     0xdeadbeef
#define CAM_INVALID_BLOCKPOS    0xdeadbeef
#define CAM_INVALID_PAYLOADLEN  0xdeadbeef
#define CAM_INVALID_UINT32_FROM_HEX_STRING  0xdeadbeef


#define CAM_OPTNAME_LEN 16
#define CAM_PTNNAME_LEN 16
#define CAM_PTNSTR_LEN  64


typedef struct camrule camrule_t;
struct camrule
{
    char      optName[CAM_OPTNAME_LEN+1]; // 0,   "add"
    uint32_t  ptnId;          // 1
    char      ptnName[CAM_PTNNAME_LEN+1]; // 2
    uint32_t  svcId;          // 3
    uint32_t  tableSel;       // 4,   "1"
    uint8_t   ptnPri;         // 5,   "5"
    uint8_t   isCheckTCP;     // 6
    uint8_t   isCheckUDP;     // 7
    uint8_t   isCheckPort;    // 8
    uint8_t   ptnLowPri;      // 9,   "5"
    //char*   unknown;        // 10,  "64"
    //char*   unknown2;       // 11,  "#7"
    uint8_t   ptnType;        // 12
    char      ptnStr[CAM_PTNSTR_LEN+1]; // 13
    uint32_t  strMask[8];     // 14 - 21
    uint8_t   strMatchMode;   // 22
    uint8_t   isAfterAnchor;  // 23
    uint8_t   isChkCapital;   // 24
    uint32_t  blockPos;       // 25
    uint32_t  bytePos;        // 26
    uint8_t   anchorId;       // 27
    uint8_t   specPtnId;      // 28
    uint32_t  payloadLen;     // 29
    uint32_t  camIdx;         // 30
    uint8_t   isAvoidErased;  // 31, "1" / "0"

    uint8_t*  cpl_ptn;
    uint8_t*  cpl_mask;
    uint32_t  cpl_ptn_len;
};

typedef struct camrule_match_result camrule_match_result_t;
struct camrule_match_result
{
    //uint32_t  ptnId;
    //char*     ptnName;
    uint16_t  start;
    camrule_t* rule;
};

static inline
void camrule_init(camrule_t* rule)
{
    int i;
    if(rule == NULL)
        return;

    strcpy(rule->optName, "add");
    rule->tableSel = 1;
    rule->ptnPri = rule->ptnLowPri = 5;
    //rule->unknown  = "64";
    //rule->unknown2 = "#7";
    rule->isAvoidErased = 1;

    rule->strMatchMode = MM_NULL;
    rule->ptnType = PT_NULL;
    rule->anchorId = AT_NULL;
    rule->specPtnId = SP_NULL;
    rule->blockPos = CAM_INVALID_BLOCKPOS;
    rule->bytePos = CAM_INVALID_BYTEPOS;
    rule->payloadLen = CAM_INVALID_PAYLOADLEN;

    for(i=0; i<8; ++i)
        rule->strMask[i] = CAM_INVALID_UINT32_FROM_HEX_STRING;

    rule->cpl_ptn = NULL;
    rule->cpl_mask = NULL;
    rule->cpl_ptn_len = 0;
}

static inline
int camrule_equal (const camrule_t* a, const camrule_t* b)
{

    if( strcmp(a->optName, b->optName) != 0 ||
        a->ptnId     != b->ptnId      ||
        a->svcId     != b->svcId      ||
        strcmp(a->ptnName, b->ptnName) != 0 ||
        a->tableSel  != b->tableSel   ||
        a->ptnPri    != b->ptnPri     ||
        a->ptnLowPri != b->ptnLowPri  ||
        a->isCheckTCP    != b->isCheckTCP ||
        a->isCheckUDP    != b->isCheckUDP ||
        a->isCheckPort   != b->isCheckPort ||
        //a->unknown   != b->unknown    ||
        //a->unknown2  != b->unknown2   ||
        a->ptnType   != b->ptnType    ||
        strcmp(a->ptnStr, b->ptnStr) != 0 ||
        a->strMask[0] != b->strMask[0] ||
        a->strMask[1] != b->strMask[1] ||
        a->strMask[2] != b->strMask[2] ||
        a->strMask[3] != b->strMask[3] ||
        a->strMask[4] != b->strMask[4] ||
        a->strMask[5] != b->strMask[5] ||
        a->strMask[6] != b->strMask[6] ||
        a->strMask[7] != b->strMask[7] ||
        a->strMatchMode  != b->strMatchMode   ||
        a->isAfterAnchor != b->isAfterAnchor  ||
        a->isChkCapital  != b->isChkCapital   ||
        a->anchorId  != b->anchorId   ||
        a->specPtnId != b->specPtnId  ||
        a->payloadLen != b->payloadLen)
        return 0;

    if(a->strMatchMode == MM_SHIFT)
        return 1;
    else if(a->blockPos != b->blockPos ||
            a->bytePos  != b->bytePos)
        return 0;

    return 0;
}

int camrule_compile(camrule_t* rule);
int camrule_match(camrule_t* rule, 
                    const uint8_t* data, uint32_t len, 
                    camrule_match_result_t* result);


///////////////////////////////////////////////////////////////

#define CAMRULE_MAX     1024
#ifndef MAX_PATH
#define MAX_PATH        260
#endif

typedef struct camrule_ctx camrule_ctx_t;
struct camrule_ctx
{
    char path[MAX_PATH];
    FILE* fp;
    camrule_t* rules[CAMRULE_MAX];
    uint32_t   rules_cnt;
};

static inline
void camrule_ctx_init(camrule_ctx_t* ctx)
{
    int i;
    if(NULL == ctx)
        return;

    ctx->path[0] = 0;
    ctx->fp = NULL;
    for(i=0; i<CAMRULE_MAX; i++)
        ctx->rules[i] = NULL;
    ctx->rules_cnt = 0;
}

int camrule_ctx_load(camrule_ctx_t* ctx, const char* path);
int camrule_ctx_match(camrule_ctx_t* ctx, 
            const uint8_t* data, uint32_t len,
            uint32_t ipproto,
            camrule_match_result_t* reult);

#endif /* __CAMRULE_H__ */

