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
#ifndef DIALOGMULTIDISASMSIGNATURE_H
#define DIALOGMULTIDISASMSIGNATURE_H

#include <QDialog>
#include <QClipboard>
#include "xlineedithex.h"
#include "xdisasmview.h"
#include "xcapstone.h"

namespace Ui {
class DialogMultiDisasmSignature;
}

class DialogMultiDisasmSignature : public QDialog
{
    Q_OBJECT

    struct SIGNATURE_RECORD
    {
        qint64 nAddress;
        QString sOpcode;
        QByteArray baOpcode;
        qint32 nDispOffset;
        qint32 nDispSize;
        qint32 nImmOffset;
        qint32 nImmSize;
        bool bIsConst;
    };

public:
    explicit DialogMultiDisasmSignature(QWidget *pParent,QIODevice *pDevice,qint64 nOffset,qint64 nAddress,csh handle);
    ~DialogMultiDisasmSignature();
    void reload();

private slots:
    void on_pushButtonOK_clicked();
    void reloadSignature();
    void on_checkBoxSpaces_toggled(bool bChecked);
    void on_checkBoxUpper_toggled(bool bChecked);
    void on_lineEditWildcard_textChanged(const QString &sText);
    void on_pushButtonCopy_clicked();
    QString replaceWild(QString sString, qint32 nOffset,qint32 nSize,QChar cWild);
    void on_spinBoxCount_valueChanged(int nValue);

    void on_comboBoxMethod_currentIndexChanged(int nIndex);

private:
    Ui::DialogMultiDisasmSignature *ui;
    QIODevice *g_pDevice;
    qint64 g_nOffset;
    qint64 g_nAddress;
    csh g_handle;
    QList<SIGNATURE_RECORD> g_listRecords;
};

#endif // DIALOGMULTIDISASMSIGNATURE_H
