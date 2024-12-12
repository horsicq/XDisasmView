/* Copyright (c) 2020-2024 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef XMULTIDISASMWIDGET_H
#define XMULTIDISASMWIDGET_H

#include <QComboBox>

#include "xdisasmview.h"
#include "xformats.h"

namespace Ui {
class XMultiDisasmWidget;
}

class XMultiDisasmWidget : public XShortcutsWidget {
    Q_OBJECT

public:
    struct OPTIONS {
        XBinary::FT fileType;
        XADDR nStartAddress;  // For FT_REGION
        XADDR nInitAddress;
        QString sTitle;
        bool bModeFixed;  // TODO Check
        QString sArch;
        bool bMenu_Hex;
        bool bHideReadOnly;
    };

    explicit XMultiDisasmWidget(QWidget *pParent = nullptr);
    ~XMultiDisasmWidget();

    void setData(QIODevice *pDevice, const OPTIONS &options);
    void setDevice(QIODevice *pDevice);
    void setXInfoDB(XInfoDB *pXInfoDB);
    void setGlobal(XShortcuts *pShortcuts, XOptions *pXOptions);
    virtual void setReadonly(bool bState);
    void setReadonlyVisible(bool bState);
    void setEdited(qint64 nDeviceOffset, qint64 nDeviceSize);
    void goToAddress(XADDR nAddress); // TODO remove use setLocation
    void goToOffset(qint64 nOffset); // TODO remove use setLocation
    virtual void setLocation(quint64 nLocation, qint32 nLocationType, qint64 nSize);
    virtual void adjustView();
    void setWidgetFocus();
    virtual void reloadData(bool bSaveSelection);

private:
    void addMode(XBinary::DM disasmMode);
    void reloadFileType();
    void adjustMode();
    void getSymbols();

private slots:
    void on_comboBoxMode_currentIndexChanged(int nIndex);
    void on_checkBoxReadonly_toggled(bool bChecked);
    void on_comboBoxType_currentIndexChanged(int nIndex);
    void adjustVisitedState();
    void on_toolButtonVisitedPrev_clicked();
    void on_toolButtonVisitedNext_clicked();
    void on_toolButtonAnalyze_clicked();

protected:
    virtual void registerShortcuts(bool bState);

signals:
    void deviceSizeChanged(qint64 nOldSize, qint64 nNewSize);
    void showOffsetHex(qint64 nOffset);

private:
    Ui::XMultiDisasmWidget *ui;
    QIODevice *g_pDevice;
    XInfoDB *g_pXInfoDB;
    OPTIONS g_options;
};

#endif  // XMULTIDISASMWIDGET_H
