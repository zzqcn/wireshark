/**
 * @file dpi.h
 * @brief Common data structures and functions for DPI.
 * @author zzq
 * @version 1.0
 * @date 2015-09-15
 */

#ifndef __DPI_H__
#define __DPI_H__

#define DPI_NAME_LEN    32

typedef struct _dpi_t
{
    gboolean valid;
    guint32  class_id;
    guint32  subclass_id;
    guint32  pattern_id;
    gchar    class_name[DPI_NAME_LEN];
    gchar    subclass_name[DPI_NAME_LEN];
    gchar    pattern_name[DPI_NAME_LEN];
    gint8    priority;
} dpi_t;

#endif /* __DPI_H__ */

