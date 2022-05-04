/* Copyright (c) 2020-2022 hors<horsicq@gmail.com>
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
#include "xformats.h"
#include "xdisasmview.h"
#include "dialogxsymbols.h"

namespace Ui {
class XMultiDisasmWidget;
}

class XMultiDisasmWidget : public XShortcutsWidget
{
    Q_OBJECT

public:
    struct OPTIONS
    {
        XBinary::FT fileType;
        XADDR nStartAddress; // For FT_REGION
        XADDR nInitAddress;
        QString sTitle;
        QString sArch;
    };

    explicit XMultiDisasmWidget(QWidget *pParent=nullptr);
    ~XMultiDisasmWidget();

    void setData(QIODevice *pDevice,OPTIONS options);
    void goToAddress(XADDR nAddress);
    void setCurrentIPAddress(XADDR nAddress);
    void goToOffset(qint64 nOffset);
    void setGlobal(XShortcuts *pShortcuts,XOptions *pXOptions);
    void setReadonly(bool bState);
    void setEdited(bool bState);
    void setXIinfoDB(XInfoDB *pXInfoDB);

private:
    void addMode(XBinary::DM disasmMode);
    void reloadFileType();
    void adjustMode();

private slots:
    void on_comboBoxType_currentIndexChanged(int nIndex);
    void on_comboBoxMode_currentIndexChanged(int nIndex);
    void errorMessageSlot(QString sErrorMessage);
    void on_pushButtonSymbols_clicked();

protected:
    virtual void registerShortcuts(bool bState);

private:
    Ui::XMultiDisasmWidget *ui;
    QIODevice *g_pDevice;
    OPTIONS g_options;
};

#endif // XMULTIDISASMWIDGET_H
