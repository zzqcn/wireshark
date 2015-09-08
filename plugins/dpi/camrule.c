/**
 * @file
 * @brief CAM特征.
 * @author Zhao Ziqing <psyc209@163.com>
 * @date 2015.09.07
 * @version 0.1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <epan/value_string.h>
#include <epan/ipproto.h>
#include "camrule.h"


const char* str_matchmode[5] =
{ "NULL", "滑动匹配", "固定偏移", "NULL", "锚点匹配" };

const char* str_ptntype[3] =
{ "NULL", "ASCII", "HEX" };

const char* str_anchortype[9] =
{
    "HTTP/m.n", "User-Agent", "Content-Type", "http://",
    "Host", "X-Online-Host", "0d0a0d0a", "Referer", "NULL"
};

const char* str_specptn[5] =
{ "NULL", "GET", "POST", "http应答", "wap应答" };


static inline
int is_hex_char(char ch)
{
    if(isdigit(ch))
        return 1;
    if(ch >= 'a' && ch <= 'f')
        return 1;
    if(ch >= 'A' && ch <= 'F')
        return 1;
    return 0;
}


#define IS_SPACE(c)  ((c) == ' ' || (c) == '\t')
 
static inline
char* trim(char *str)
{
    size_t len;
    char *p, *end;

    p = str;
    if (p == NULL)
        return NULL;

    while(IS_SPACE(*p))
        p++;
    len = strlen(p);
    if (len < 1)
        return str;

    end = p + len - 1;
    while(IS_SPACE(*end))
        end--;
    *(++end) = '\0';

    end = p;
    str = p;
    while(*end != '\0')
        *(p++) = *(end++);
    *p = '\0';

    return str;
}

#ifndef __GNUC__
#ifndef ssize_t
typedef int ssize_t;
#endif
ssize_t getline(char** line, size_t* n, FILE* fp)
{
    ssize_t c, i;
    
    if(NULL == line || NULL == fp || NULL == n)
        return -1;
    if(NULL == *line)
        *line = malloc(2048);
    
    i = 0;
    while((c = fgetc(fp)) != EOF && c != '\n' && i<2046)
        (*line)[i++]=c;
    if(c == EOF && i==0)
        return -1;
    if(c == '\n')
        (*line)[i++]=c;
    (*line)[i] = '\0';
    *n = i;
    
    return i;
}

#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif

/*
 * @brief Find the first occurrence of find in s, ignore case.
 * @ref http://www.opensource.apple.com/source/Libc/Libc-320.1.3/string/FreeBSD/strcasestr.c
 */
static inline
char *strcasestr(s, find)
    const char *s, *find;
{
    char c, sc;
    size_t len;

    if ((c = *find++) != 0) {
        c = tolower((unsigned char)c);
        len = strlen(find);
        do {
            do {
                if ((sc = *s++) == 0)
                    return (NULL);
            } while ((char)tolower((unsigned char)sc) != c);
        } while (strncasecmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}
#endif


int get_maskstr_from_ptnstr(const char* ptnStr,
                             char* maskStr[8],
                             int type,
                             int chkCapital)
{
    int mi = 0;
    size_t i;
    char m[8][64] = {{0}};
    size_t ptn_len = strlen(ptnStr);
    size_t mi_len;

    // TODO: 现在代码有点丑陋
    if(ptn_len < 1)
        return -1;
    if(type == PT_ASCII && ptn_len > 32)
        return -1;
    if(type == PT_HEX && ptn_len > 64)
        return -1;


    for(i=0; i<ptn_len; ++i)
    {
        char ch = ptnStr[i];

        if(type == PT_ASCII) // ASCII
        {
            if(isalpha(ch))
            {
                if(chkCapital)
                    strcat(m[mi], "ff");
                else
                    strcat(m[mi], "df");
            }
            else if(ch == '*' || ch == '?')
                strcat(m[mi], "00");
            else
                strcat(m[mi], "ff");
        }
        else if(type == PT_HEX) // HEX
        {
            if(!is_hex_char(ch) && ch != '*' && ch != '?')
                return -1;

            (ch == '*' || ch == '?') ?
                strcat(m[mi], "0") : strcat(m[mi], "f");

        }

        if(strlen(m[mi]) == 8)
            mi++;
    }

    mi_len = strlen(m[mi]);
    if(mi_len > 0 && mi_len < 8)
    {
        for(i=0; i<8-mi_len; i++)
            strcat(m[mi], "0");
        mi++;
    }

    for(i=0; i<(size_t)8-mi; i++)
        strcpy(m[mi+i], "0");

    for(i=0; i<8; i++)
        strncpy(maskStr[i], m[i], CAM_PTNSTR_LEN);

    return 0;
}

int camrule_compile(camrule_t* rule)
{
    int ret = 0;
    uint32_t i;

    if(rule->ptnType == PT_ASCII)
    {
        rule->cpl_ptn_len = (uint32_t)strlen(rule->ptnStr);
        rule->cpl_ptn = (uint8_t*) malloc(rule->cpl_ptn_len);
        for(i=0; i<rule->cpl_ptn_len; ++i)
            rule->cpl_ptn[i] = (uint8_t) rule->ptnStr[i];
    }
    else if(rule->ptnType == PT_HEX)
    {
        char ss[8] = {0};
        uint32_t slen = (uint32_t)strlen(rule->ptnStr);
        rule->cpl_ptn_len = slen/2;
        rule->cpl_ptn = (uint8_t*) malloc(rule->cpl_ptn_len);
        for(i=0; i<slen; i+=2)
        {
            if(rule->ptnStr[i] == '*' || rule->ptnStr[i] == '?')
                rule->ptnStr[i] = '0';

            //string ss = m_rule.ptnStr.substr(i, 2);
            strncpy(ss, rule->ptnStr+i, 2);
            if(strcmp(ss, "00") == 0)
                rule->cpl_ptn[i/2] = 0;
            else
            {
                unsigned long ul = strtoul(ss, 0, 16);
                if(0 == ul)
                {
                    return -1;
                }
                else
                    rule->cpl_ptn[i/2] = (uint8_t) ul;
            }
        }
    }

    if(rule->cpl_ptn != NULL && rule->cpl_ptn_len != 0)
    {
        int bit_shift = 0, mi = 0;
        uint8_t mask;

        rule->cpl_mask = (uint8_t*) malloc(rule->cpl_ptn_len);

        // TODO: ASCII时的检查
        for(i=0; i<rule->cpl_ptn_len; ++i)
        {
            mi = i/4;
            bit_shift = 4 - (i+1)%4;
            mask = (rule->strMask[mi] >> (bit_shift*8)) & 0x000000ff;

            // HACK: 满足isChkCapital规则，见kgtzdef.h
            if(mask == 0xff && isalpha(rule->cpl_ptn[i]))
            {
                if(!rule->isChkCapital)
                    mask = 0xdf;
            }

            rule->cpl_mask[i] = mask;
        }
    }

    return ret;
}

static int camrule_domatch(camrule_t* rule, const uint8_t* data)
{
    int ret = 1;
    uint32_t i;

    assert(data != NULL && rule->cpl_ptn != NULL && rule->cpl_ptn_len > 0);

    // TODO: ASCII时的检查
    for(i=0; i<rule->cpl_ptn_len; ++i)
    {
        //TRACE2("%.2x, %.2x\n", data[i], ptn[i]);
        if(rule->cpl_mask[i] == 0)
            continue;
        if((data[i] & rule->cpl_mask[i]) != (rule->cpl_ptn[i] & rule->cpl_mask[i]))
        {
            ret = 0;
            break;
        }
    }

    return ret;
}


const char* ANCHOR_HTTP10 = "HTTP/1.0";
const char* ANCHOR_HTTP11 = "HTTP/1.1";
const char* ANCHOR_USER_AGENT = "User-Agent: ";
const char* ANCHOR_CONTENT_TYPE = "Content-Type: ";
const char* ANCHOR_HTTP = "http://";
const char* ANCHOR_HOST = "Host: ";
const char* ANCHOR_XONLINE_HOST = "X-Online-Host: ";
const char* ANCHOR_0D0A = "\r\n";
const char* ANCHOR_REFERER = "Referer: ";

int camrule_match(camrule_t* rule, const uint8_t* data, uint32_t len,
        camrule_match_result_t* result)
{
    int ret = 0;
    size_t i;
    size_t start = 0;

    if(NULL == data || len < 1 || NULL == result)
        return 0;

    // 优先检测通用特征
    // FIX: 当前仅支持GET,POST
    if(rule->specPtnId != SP_NULL)
    {
        if(len < 4)
            return 0;
        switch (rule->specPtnId)
        {
        case SP_GET:
            if(memcmp(data, "GET", 3))
                return 0;
            break;
        case SP_POST:
            if(memcmp(data, "POST", 4))
                return 0;
            break;
        case SP_HTTP_ACK:
            break;
        case SP_WAP_ACK:
            break;
        default:
            return 0;
            break;
        }
    }


    // 检测payloadLen
    if(rule->payloadLen != 0)
    {
        if(len != rule->payloadLen)
            return 0;
    }

    if(rule->cpl_ptn == NULL || rule->cpl_ptn_len == 0 || len < rule->cpl_ptn_len)
        return 0;

    if(rule->strMatchMode == MM_SHIFT)
    {
        for(i=0; i<=len-rule->cpl_ptn_len; ++i)
        {
            if(camrule_domatch(rule, data+i))
            {
                start = i;
                result->start = start;
                //result->ptnId = rule->ptnId;
                //result->ptnName = rule->ptnName;
                result->rule = rule;
                return 1;
            }
        }
    }
    else if(rule->strMatchMode == MM_FIXED)
    {
        int offset = rule->blockPos*16 + rule->bytePos;

        if((len-offset) < rule->cpl_ptn_len)
            return 0;

        if(camrule_domatch(rule, data+offset))
        {
            start = offset;
            result->start = start;
            //result->ptnId = rule->ptnId;
            //result->ptnName = rule->ptnName;
            result->rule = rule;
            return 1;
        }
    }
    else if(rule->strMatchMode == MM_ANCHOR)
    {
        size_t offset;
        const char *anchor, *anchor2;
        const char* psz = (char*)data;
        size_t anchor_pos, odoa_pos;
        char* find_ret;

        if(len < 4)
            return 0;

        for(i=0; i<4; ++i)
        {
            if( data[i] > 0x7e ||
               (data[i] < 0x20 && 
                !(data[i] == '\t' || data[i] == '\r' || data[i] == '\n'))
              )
                return 0;
        }

        switch (rule->anchorId)
        {
        case AT_HTTP_MN:
            anchor = ANCHOR_HTTP10;
            anchor2 = ANCHOR_HTTP11; 
            break;
        case AT_USER_AGENT:
            anchor = ANCHOR_USER_AGENT;
            break;
        case AT_CONTENT_TYPE:
            anchor = ANCHOR_CONTENT_TYPE;
            break;
        case AT_HTTP:
            anchor = ANCHOR_HTTP;
            break;
        case AT_HOST:
            anchor = ANCHOR_HOST;
            break;
        case AT_X_ONLINE_HOST:
            anchor = ANCHOR_XONLINE_HOST;
            break;
        case AT_0D0A0D0A:
            anchor = ANCHOR_0D0A;
            break;
        case AT_REFERER:
            anchor = ANCHOR_REFERER;
            break;
        default:
            return 0;
        }

        find_ret = strcasestr(psz, anchor);
        if(find_ret == NULL && rule->anchorId == AT_HTTP_MN)
            find_ret = strcasestr(psz, anchor2);
        if(find_ret == NULL)
            return 0;
        anchor_pos = (uint32_t)(find_ret - psz);

        if(rule->anchorId != AT_HTTP_MN)
        {
            offset = anchor_pos + strlen(anchor);
            // 正向
            if(rule->blockPos == 0 && rule->bytePos == 0)
            {
                if(rule->anchorId == AT_REFERER)
                    offset += strlen(ANCHOR_HTTP);
                if((len-offset) < rule->cpl_ptn_len)
                    return 0;

                if(camrule_domatch(rule, data+offset))
                {
                    start = offset;
                    result->start = start;
                    //result->ptnId = rule->ptnId;
                    //result->ptnName = rule->ptnName;
                    result->rule = rule;
                    return 1;
                }
            }
            // 反向
            else
            {
                //odoa_pos = payload.substr(offset).find(odoa);
                find_ret = strcasestr(psz+offset, "\r\n");
                //if(odoa_pos == string::npos)
                if(find_ret == NULL)
                    return 0;
                odoa_pos = find_ret-psz;

                //for(size_t i=offset; i < (odoa_pos-ptn_len); ++i)
                for(i=offset; i <= (offset + odoa_pos - rule->cpl_ptn_len); ++i)
                {
                    if(camrule_domatch(rule, data+i))
                    {
                        start  = i;
                        result->start = start;
                        //result->ptnId = rule->ptnId;
                        //result->ptnName = rule->ptnName;
                        result->rule = rule;
                        return 1;
                    }
                }
            } // end 正向，反向
        }
        else // AT_HTTP_MN
        {
            offset = anchor_pos;
            for(i=0; i<(anchor_pos-rule->cpl_ptn_len); ++i)
            {
                if(camrule_domatch(rule, data+i))
                {
                    start  = i;
                    result->start = start;
                    //result->ptnId = rule->ptnId;
                    //result->ptnName = rule->ptnName;
                    result->rule = rule;
                    return 1;
                }
            }
        } // end if(m_tz.anchorId...
    } // end if(m_tz.strMatchMode...

    return ret;
}


//#define DELIM_CHAR 0x2c
#define DELIM_CHAR ","
#define CHECK_RETURN(x, ret)    if(!(x)) return (ret)


int camrule_ctx_load(camrule_ctx_t* ctx, const char* path)
{
    int ret;
    char* line = NULL;
    size_t line_cnt;
    ssize_t read_cnt;
    char* str_matrix[CAMRULE_MAX][CRI_COUNT];
    char* p;
    uint32_t n_rules = 0;
    uint32_t i;

    if(NULL == ctx || NULL == path)
        return -1;
    
    ctx->fp = fopen(path, "r");
    if(NULL == ctx->fp)
        return -1;
    strcpy(ctx->path, path);

    do
    {
        char* strs[CRI_COUNT] = {NULL};
        int bad = 0;
        i = 0;

        read_cnt = getline(&line, &line_cnt, ctx->fp);
        if(read_cnt < CRI_COUNT)
        {
            if(line != NULL)
            {
                free(line);
                line = NULL;
            }
            
            if(0 == read_cnt || -1 == read_cnt)
                break;
            continue;
        }
        
        p = strtok(line, DELIM_CHAR);
        while(p != NULL)
        {
            if(i >= CRI_COUNT)
            {
                bad = 1;
                break;
            }
            strs[i++] = trim(p);
            p = strtok(NULL, DELIM_CHAR);
        }

        if(i == CRI_COUNT && bad != 1)
        {
            for(i=0; i<CRI_COUNT; i++)
            {
                str_matrix[n_rules][i] = strdup(strs[i]);
            }
            n_rules++;
        }
        free(line); line = NULL;
    }
    //while(read_cnt != -1);
    while(n_rules < CAMRULE_MAX);


    for(i=0; i<n_rules; i++)
    {
        unsigned long nVal;
        camrule_t rule;
        char** s = str_matrix[i];
        int validMask = 0;
        int k, dup;

#define  CHECK_CONTINUE(x)  if(!(x)) continue
#define  CHECK_BREAK(x)     if(!(x)) break


        strcpy(rule.optName, s[CRI_OPT_NAME]);
        CHECK_CONTINUE(strcmp(rule.optName, "add") == 0);

        nVal = strtoul(s[CRI_PTN_ID], 0, 10);
        CHECK_CONTINUE(nVal > 0);
        rule.ptnId    = (uint32_t)nVal;

        strcpy(rule.ptnName, s[CRI_PTN_NAME]);
        CHECK_CONTINUE(strlen(rule.ptnName) > 0);

        nVal = strtoul(s[CRI_SVC_ID], 0, 10);
        CHECK_CONTINUE(nVal > 0);
        rule.svcId    = (uint32_t)nVal;

        nVal = strtoul(s[CRI_TABLE_SEL], 0, 10);
        CHECK_CONTINUE(nVal == 1);
        rule.tableSel = (uint32_t)nVal;

        nVal = strtoul(s[CRI_PTN_PRI], 0, 10);
        rule.ptnPri   = nVal;
        /// 5 ///////////////////////////////////////////////////////

        rule.isCheckTCP   = (s[CRI_IS_CHECK_TCP][0] == '1');
        rule.isCheckUDP   = (s[CRI_IS_CHECK_UDP][0] == '1');
        rule.isCheckPort  = (s[CRI_IS_CHECK_PORT][0] == '1');

        nVal = strtoul(s[CRI_PTN_LOW_PRI], 0, 10);
        rule.ptnLowPri    = nVal;
        //rule.unknown      = trim(s[CRI_UNKNOWN]);
        //CHECK_CONTINUE(rule.unknown == "64");
        /// 10 ///////////////////////////////////////////////////////

        //rule.unknown2     = trim(j[CRI_UNKNOWN2]);
        //CHECK_CONTINUE(rule.unknown2 == "#7");

        nVal = strtoul(s[CRI_PTN_TYPE], 0, 10);
        CHECK_CONTINUE(nVal == PT_ASCII || nVal == PT_HEX);
        rule.ptnType      = nVal;

        // 不允许前后空格
        strcpy(rule.ptnStr, s[CRI_PTN_STR]);
        CHECK_CONTINUE(strlen(rule.ptnStr) > 0);

        rule.isChkCapital = (s[CRI_IS_CHK_CAPITAL][0] == '1');

        for(k = 0; k<8; k++)
        {
            // HACK: XXX
            // Shit
            //if(tz.ptnType == PtnType::PT_ASCII)
            //{
            //    if(tz.isChkCapital == false)
            //    {
            //        for(size_t kk=0; kk<hex_str.length(); kk+=2)
            //        {
            //            if(hex_str[kk] == 'f')
            //               hex_str[kk] = 'd';
            //        }
            //    }
            //}
            // HACK END
            nVal = strtoul(s[CRI_STR_MASK0 + k], 0, 16);
            rule.strMask[k] = (uint32_t)nVal;
            if(nVal > 0)
                validMask = 1;
        }
        CHECK_CONTINUE(validMask);

//        // 检测strMask都为0的非法情况
//        if(rule.strMask[0] == 0 && rule.strMask[1] == 0 &&
//           rule.strMask[2] == 0 && rule.strMask[3] == 0 &&
//           rule.strMask[4] == 0 && rule.strMask[5] == 0 &&
//           rule.strMask[6] == 0 && rule.strMask[7] == 0)
//        {
//            continue;
//        }
        /// 21 ///////////////////////////////////////////////////////

        nVal = strtoul(s[CRI_STR_MATCH_MODE], 0, 10);
        CHECK_CONTINUE(nVal == MM_SHIFT ||
                       nVal == MM_FIXED ||
                       nVal == MM_ANCHOR);
        rule.strMatchMode   = nVal;

        rule.isAfterAnchor    = (s[CRI_IS_AFTER_ANCHOR][0] == '1');

        nVal = strtoul(s[CRI_BLOCK_POS], 0, 10);
        CHECK_CONTINUE(nVal >= 0);
        rule.blockPos = (uint32_t)nVal;

        nVal = strtoul(s[CRI_BYTE_POS], 0, 10);
        CHECK_CONTINUE(nVal >= 0);
        rule.bytePos = (uint32_t)nVal;

        // HACK 2013.04.26
        if(rule.strMatchMode != MM_ANCHOR || s[CRI_ANCHOR_ID][0] == '8')
            rule.anchorId = AT_NULL;
        else
        {
            nVal = strtoul(s[CRI_ANCHOR_ID], 0, 10);
            CHECK_CONTINUE(nVal >= 0 && nVal < 8);
            rule.anchorId     = nVal;
        }

        nVal = strtoul(s[CRI_SPEC_PTN_ID], 0, 10);
        CHECK_CONTINUE(nVal >= 0 && nVal <= SPEC_PTN_MAX);
        rule.specPtnId        = nVal;

        nVal = strtoul(s[CRI_PAYLOAD_LEN], 0, 10);
        CHECK_CONTINUE(nVal >= 0);
        rule.payloadLen = (uint32_t)nVal;

        //vector<KGCAMRule>::iterator ret = find(m_rules.begin(), m_rules.end(), rule);
        //if(ret == m_rules.end())
        //    m_rules.push_back(rule);
        dup = 0;
        for(k=0; k<(int)ctx->rules_cnt; k++)
        {
            if(camrule_equal(ctx->rules[k], &rule))
            {
                dup = 1;
                break;
            }
        }
        
        if(dup == 0)
        {
            ctx->rules[ctx->rules_cnt] = (camrule_t*) malloc(sizeof(camrule_t));
            memcpy(ctx->rules[ctx->rules_cnt], &rule, sizeof(camrule_t));
            ret = camrule_compile(ctx->rules[ctx->rules_cnt]);
            assert(ret == 0);
            ctx->rules_cnt++;
        }
    }

//CLEAN:
    for(i=0; i<n_rules; i++)
    {
        char** s = str_matrix[i];
        int j;
        
        for(j=0; j<CRI_COUNT; j++)
        {
            if(s[j] != NULL)
            {
                free(s[j]);
                s[j] = NULL;
            }
        }
    }

    return 0;
}

int camrule_ctx_match(camrule_ctx_t* ctx, 
                const uint8_t* data, uint32_t len,
                uint32_t ipproto,
                camrule_match_result_t* result)
{
    //int ret;
    uint32_t i, max;
    //camrule_match_result_t* result;
    
    if(IP_PROTO_TCP != ipproto && IP_PROTO_UDP != ipproto)
        return 0;
    
    max = CAMRULE_MAX;
    for(i=0; i<ctx->rules_cnt; i++)
    {
        if(!ctx->rules[i]->isCheckTCP && ipproto == IP_PROTO_TCP)
            continue;
        if(!ctx->rules[i]->isCheckUDP && ipproto == IP_PROTO_UDP)
            continue;

        if(camrule_match(ctx->rules[i], data, len, result))
        {
            if(i == 0 || ctx->rules[max]->ptnLowPri < ctx->rules[i]->ptnLowPri)
                max = i;
            if(ctx->rules[max]->ptnLowPri == CAMRULE_LOWPRI_MAX)
                break;
        }
    }
    
    if(max != CAMRULE_MAX)
        return 1;
    
    return 0;
}


