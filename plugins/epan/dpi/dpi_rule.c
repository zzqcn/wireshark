#include "config.h"

#include <ctype.h>
#include <glib.h>
#include <hs.h>
#include <wsutil/wslog.h>

#include "packet-dpi.h"

typedef struct dpi_context
{
    dpi_rule_t *rule_map[DPI_MAX_RULES];
    hs_database_t *db;
    hs_scratch_t *scratch;
} dpi_context_t;

static dpi_context_t *g_context = NULL;

enum
{
    FLD_ID,
    FLD_HOST,
    FLD_PRIORITY,
    FLD_NAME,
    FLD_NUM,
};

#define COMMENT_LEAD_CHAR ('#')

/* Bypass comment and empty lines */
static inline int is_bypass_line(char *buff)
{
    int i = 0;

    /* comment line */
    if (buff[0] == COMMENT_LEAD_CHAR)
        return 1;
    /* empty line */
    while (buff[i] != '\0')
    {
        if (!isspace(buff[i]))
            return 0;
        i++;
    }
    return 1;
}

static int parse_rule(char *str, dpi_rule_t *rule)
{
    int i, dim = FLD_NUM;
    char *s, *end, *in[FLD_NUM];
    static const char *dlm = ", \t\r\n";
    unsigned long val;
    // gchar *chn_str;

    s = str;
    for (i = 0; i != dim; i++, s = NULL)
    {
        in[i] = strtok(s, dlm);
        if (NULL == in[i])
            return -1;
    }

    errno = 0;
    val = strtoul(in[FLD_ID], &end, 10);
    if (errno != 0 || val >= DPI_MAX_RULES)
        return -1;
    rule->id = (uint32_t)val;

    if (strlen(in[FLD_HOST]) >= 32)
        return -1;
    strcpy(rule->host, in[FLD_HOST]);

    errno = 0;
    val = strtoul(in[FLD_PRIORITY], &end, 10);
    if (errno != 0 || val > UINT16_MAX)
        return -1;
    rule->priority = (uint16_t)val;

    strncpy(rule->name, in[FLD_NAME], 32 - 1);

    return 0;
}

int dpi_load_rules(const char *rule_path)
{
    int ret = 0;
    FILE *fh;
    char buff[LINE_MAX];
    unsigned i, n;
    unsigned ids[DPI_MAX_RULES] = {0}, flags[DPI_MAX_RULES] = {0};
    char *exps[DPI_MAX_RULES];
    hs_compile_error_t *error;
    dpi_rule_t *rule;

    g_context = g_new0(dpi_context_t, 1);
    if (NULL == g_context)
        return -1;

    fh = fopen(rule_path, "rb");
    if (fh == NULL)
        ws_error("open DPI rule file %s failed", rule_path);

    ret = fseek(fh, 0, SEEK_SET);
    if (ret)
        ws_error("fseek DPI rule file failed");

    i = n = 0;
    while (fgets(buff, LINE_MAX, fh) != NULL)
    {
        if (is_bypass_line(buff))
            continue;

        if (n >= DPI_MAX_RULES - 1)
        {
            ws_warning("DPI rule capacity %d reached", n);
            break;
        }

        rule = g_new0(dpi_rule_t, 1);
        if (NULL == rule)
            return -1;

        if (parse_rule(buff, rule) != 0)
            ws_error("%s Line %u: parse rules error", rule_path, i);

        g_context->rule_map[rule->id] = rule;
        ids[i] = rule->id;
        flags[i] = HS_FLAG_CASELESS;
        exps[i] = rule->host;

        i++;
        n++;
    }
    fclose(fh);

    ret = hs_compile_multi(exps, flags, ids, n, HS_MODE_BLOCK, NULL, &g_context->db, &error);
    if (ret != HS_SUCCESS)
    {
        if (error->expression < 0)
            ws_error("regex compile error: %s", error->message);
        else
            ws_error("regex compile error: regex '%s' failed with error '%s'", exps[error->expression], error->message);
        hs_free_compile_error(error);
        goto fail;
    }

    ret = hs_alloc_scratch(g_context->db, &g_context->scratch);
    if (ret != HS_SUCCESS)
    {
        ws_error("regex alloc scratch failed");
        goto fail;
    }

    return 0;

fail:
    if (g_context != NULL)
    {
        g_free(g_context);
        g_context = NULL;
    }

    return -1;
}

int match_callback(unsigned int id,
                   unsigned long long from _U_,
                   unsigned long long to _U_,
                   unsigned int flags _U_,
                   void *context)
{
    uint32_t *rule_id = (uint32_t *)context;

    if (id > *rule_id)
    {
        *rule_id = id;
    }

    return 0;
}

dpi_rule_t *dpi_match(const char *data, uint32_t data_len)
{
    int ret;
    dpi_rule_t *rule = NULL;
    uint32_t rule_id = 0;

    ret = hs_scan(g_context->db, data, data_len, 0, g_context->scratch, match_callback, &rule_id);
    if (ret != HS_SUCCESS && ret != HS_SCAN_TERMINATED)
        return NULL;
    rule = g_context->rule_map[rule_id];

    return rule;
}
