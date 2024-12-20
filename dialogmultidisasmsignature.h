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
#ifndef DIALOGMULTIDISASMSIGNATURE_H
#define DIALOGMULTIDISASMSIGNATURE_H

#include "dialogsearchsignatures.h"
#include "xabstracttableview.h"
#include "xcapstone.h"
#include "xlineedithex.h"
#include "xshortcutsdialog.h"

namespace Ui {
class DialogMultiDisasmSignature;
}

class DialogMultiDisasmSignature : public XShortcutsDialog {
    Q_OBJECT

public:
    explicit DialogMultiDisasmSignature(QWidget *pParent);
    ~DialogMultiDisasmSignature();

    virtual void adjustView();

    void setData(QIODevice *pDevice, qint64 nOffset, XBinary::_MEMORY_MAP *pMemoryMap, csh handle);
    void reload();

private slots:
    void on_pushButtonOK_clicked();
    void reloadSignature();
    void on_checkBoxSpaces_toggled(bool bChecked);
    void on_checkBoxUpper_toggled(bool bChecked);
    void on_lineEditWildcard_textChanged(const QString &sText);
    void on_pushButtonCopy_clicked();
    void on_spinBoxCount_valueChanged(int nValue);
    void on_comboBoxMethod_currentIndexChanged(int nIndex);
    void on_pushButtonScan_clicked();

protected:
    virtual void registerShortcuts(bool bState);

private:
    Ui::DialogMultiDisasmSignature *ui;
    QIODevice *g_pDevice;
    qint64 g_nOffset;
    XBinary::_MEMORY_MAP *g_pMemoryMap;
    csh g_handle;
    QList<XCapstone::SIGNATURE_RECORD> g_listRecords;
    qint32 g_nSymbolWidth;
};

#endif  // DIALOGMULTIDISASMSIGNATURE_H
