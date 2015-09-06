/* interface_tree.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "interface_tree.h"

#ifdef HAVE_LIBPCAP
#include "ui/capture_globals.h"
#endif
#include "ui/iface_lists.h"
#include "ui/utf8_entities.h"
#include "ui/ui_util.h"

#include "qt_ui_utils.h"
#include "sparkline_delegate.h"
#include "wireshark_application.h"

#include <QLabel>
#include <QHeaderView>
#include <QTimer>

const int stat_update_interval_ = 1000; // ms

InterfaceTree::InterfaceTree(QWidget *parent) :
    QTreeWidget(parent)
#ifdef HAVE_LIBPCAP
    ,stat_cache_(NULL)
    ,stat_timer_(NULL)
#endif // HAVE_LIBPCAP
{
    QTreeWidgetItem *ti;

    qRegisterMetaType< PointList >( "PointList" );

    header()->setVisible(false);
    setRootIsDecorated(false);
    setUniformRowHeights(true);
    setColumnCount(2);
    setSelectionMode(QAbstractItemView::ExtendedSelection);
    setAccessibleName(tr("Welcome screen list"));

    setItemDelegateForColumn(1, new SparkLineDelegate());
    setDisabled(true);

    ti = new QTreeWidgetItem();
    ti->setText(0, tr("Waiting for startup" UTF8_HORIZONTAL_ELLIPSIS));
    addTopLevelItem(ti);
    resizeColumnToContents(0);

    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(getInterfaceList()));
    connect(this, SIGNAL(itemSelectionChanged()), this, SLOT(updateSelectedInterfaces()));
}

InterfaceTree::~InterfaceTree() {
#ifdef HAVE_LIBPCAP
    QTreeWidgetItemIterator iter(this);

    if (stat_cache_) {
      capture_stat_stop(stat_cache_);
      stat_cache_ = NULL;
    }

    while (*iter) {
        QList<int> *points;

        points = (*iter)->data(1, Qt::UserRole).value<QList<int> *>();
        delete(points);
        ++iter;
    }
#endif // HAVE_LIBPCAP
}

void InterfaceTree::hideEvent(QHideEvent *evt) {
    Q_UNUSED(evt);

#ifdef HAVE_LIBPCAP
    if (stat_timer_) stat_timer_->stop();
    if (stat_cache_) {
        capture_stat_stop(stat_cache_);
        stat_cache_ = NULL;
    }
#endif // HAVE_LIBPCAP
}

void InterfaceTree::showEvent(QShowEvent *evt) {
    Q_UNUSED(evt);

#ifdef HAVE_LIBPCAP
    if (stat_timer_) stat_timer_->start(stat_update_interval_);
#endif // HAVE_LIBPCAP
}

void InterfaceTree::resizeEvent(QResizeEvent *evt)
{
    Q_UNUSED(evt);
    int max_if_width = width() * 2 / 3; // Arbitrary

    setUpdatesEnabled(false);
    resizeColumnToContents(0);
    if (columnWidth(0) > max_if_width) {
        setColumnWidth(0, max_if_width);
    }
    setUpdatesEnabled(true);
}

void InterfaceTree::getInterfaceList()
{
#ifdef HAVE_LIBPCAP
    GList *if_list;
    int err;
    gchar *err_str = NULL;

    clear();

    if_list = capture_interface_list(&err, &err_str,main_window_update);
    if_list = g_list_sort(if_list, if_list_comparator_alph);

    if (if_list == NULL) {
        QTreeWidgetItem *ti = new QTreeWidgetItem();
        QLabel *err_label;

        if (err == CANT_GET_INTERFACE_LIST || err == DONT_HAVE_PCAP) {
            err_label = new QLabel(gchar_free_to_qstring(err_str));
        } else {
            err_label = new QLabel("No interfaces found");
        }
        err_label->setWordWrap(true);

        setColumnCount(1);
        addTopLevelItem(ti);
        setItemWidget(ti, 0, err_label);
        resizeColumnToContents(0);
        return;
    }

    // XXX Do we need to check for this? capture_interface_list returns an error if the length is 0.
    if (g_list_length(if_list) > 0) {
        interface_t device;
        setDisabled(false);

        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            QList<int> *points;

            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

            /* Continue if capture device is hidden */
            if (device.hidden) {
                continue;
            }

            QTreeWidgetItem *ti = new QTreeWidgetItem();
            ti->setText(0, QString().fromUtf8(device.display_name));
            ti->setData(0, Qt::UserRole, QString(device.name));
            points = new QList<int>();
            ti->setData(1, Qt::UserRole, qVariantFromValue(points));
            addTopLevelItem(ti);
            // XXX Add other device information
            resizeColumnToContents(1);
            if (strstr(prefs.capture_device, device.name) != NULL) {
                device.selected = TRUE;
                global_capture_opts.num_selected++;
                global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                g_array_insert_val(global_capture_opts.all_ifaces, i, device);
            }
            if (device.selected) {
                ti->setSelected(true);
            }
        }
    }
    free_interface_list(if_list);
    resizeEvent(NULL);

    if (!stat_timer_) {
        updateStatistics();
        stat_timer_ = new QTimer(this);
        connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
        stat_timer_->start(stat_update_interval_);
    }
#else
    QTreeWidgetItem *ti = new QTreeWidgetItem();

    clear();
    setColumnCount(1);
    ti->setText(0, tr("Interface information not available"));
    addTopLevelItem(ti);
    resizeColumnToContents(0);
#endif // HAVE_LIBPCAP
}

void InterfaceTree::getPoints(int row, PointList *pts)
{
    QTreeWidgetItemIterator iter(this);
    //qDebug("iter;..!");

    for (int i = 0; (*iter); i++)
    {
        if (row == i)
        {
            //qDebug("found! row:%d", row);
            QString device_name = (*iter)->data(0, Qt::UserRole).value<QString>();
            QList<int> *punkt = (*iter)->data(1, Qt::UserRole).value<QList<int> *>();
            for (int j = 0; j < punkt->length(); j++)
            {
                pts->append(punkt->at(j));
            }
            //pts = new QList<int>(*punkt);
            //pts->operator =(punkt);
            //pts = punkt;
            //pts->append(150);
            //qDebug("done");
            return;
        }
        iter++;
    }
}

void InterfaceTree::updateStatistics(void) {
#ifdef HAVE_LIBPCAP
    interface_t device;
    guint diff, if_idx;
    struct pcap_stat stats;

    if (!stat_cache_) {
        // Start gathering statistics using dumpcap
        // We crash (on OS X at least) if we try to do this from ::showEvent.
        stat_cache_ = capture_stat_start(&global_capture_opts);
    }
    if (!stat_cache_) return;

    QTreeWidgetItemIterator iter(this);
    while (*iter) {
        QList<int> *points;

        for (if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
            QString device_name = (*iter)->data(0, Qt::UserRole).value<QString>();
            if (device_name.compare(device.name) || device.hidden || device.type == IF_PIPE)
                continue;

            diff = 0;
            if (capture_stats(stat_cache_, device.name, &stats)) {
                if ((int)(stats.ps_recv - device.last_packets) >= 0) {
                    diff = stats.ps_recv - device.last_packets;
                }
                device.last_packets = stats.ps_recv;
            }

            points = (*iter)->data(1, Qt::UserRole).value<QList<int> *>();
            points->append(diff);
            update(indexFromItem((*iter), 1));
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, if_idx);
            g_array_insert_val(global_capture_opts.all_ifaces, if_idx, device);
        }
        iter++;
    }
#endif // HAVE_LIBPCAP
}

void InterfaceTree::updateSelectedInterfaces()
{
#ifdef HAVE_LIBPCAP
    QTreeWidgetItemIterator iter(this);

    global_capture_opts.num_selected = 0;

    while (*iter) {
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            QString device_name = (*iter)->data(0, Qt::UserRole).value<QString>();
            interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device_name.compare(QString().fromUtf8(device.name)) == 0) {
                if (!device.locked) {
                    if ((*iter)->isSelected()) {
                        device.selected = TRUE;
                        global_capture_opts.num_selected++;
                    } else {
                        device.selected = FALSE;
                    }
                    device.locked = TRUE;
                    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                    g_array_insert_val(global_capture_opts.all_ifaces, i, device);

                    emit interfaceUpdated(device.name, device.selected);

                    device.locked = FALSE;
                    global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                    g_array_insert_val(global_capture_opts.all_ifaces, i, device);
                }
                break;
            }
        }
        iter++;
    }
#endif // HAVE_LIBPCAP
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
