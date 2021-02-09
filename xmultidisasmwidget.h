// copyright (c) 2020-2021 hors<horsicq@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#ifndef XMULTIDISASMWIDGET_H
#define XMULTIDISASMWIDGET_H

#include "xformats.h"
#include <QComboBox>
#include "xdisasmview.h"

namespace Ui {
class XMultiDisasmWidget;
}

class XMultiDisasmWidget : public QWidget
{
    Q_OBJECT

public:
    explicit XMultiDisasmWidget(QWidget *pParent=nullptr);
    ~XMultiDisasmWidget();

    void setData(QIODevice *pDevice, XBinary::FT fileType, qint64 nInitAddress);
    void goToAddress(qint64 nAddress);
    void goToOffset(qint64 nOffset);
    void setShortcuts(XShortcuts *pShortcuts);

signals:
    void errorMessage(QString sText);

private:
    void addMode(XBinary::DM disasmMode);
    void reloadFileType();

private slots:
    void on_comboBoxType_currentIndexChanged(int nIndex);
    void on_comboBoxMode_currentIndexChanged(int nIndex);

private:
    Ui::XMultiDisasmWidget *ui;
    QIODevice *g_pDevice;
    XBinary::FT g_fileType;
    qint64 g_nInitAddress;
};

#endif // XMULTIDISASMWIDGET_H
