/* Copyright (c) 2020-2025 hors<horsicq@gmail.com>
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
#include "dialogmultidisasmsignature.h"

#include "ui_dialogmultidisasmsignature.h"

DialogMultiDisasmSignature::DialogMultiDisasmSignature(QWidget *pParent) : XShortcutsDialog(pParent, false), ui(new Ui::DialogMultiDisasmSignature)
{
    ui->setupUi(this);

    this->m_pDevice = nullptr;
    this->m_nOffset = 0;
    this->m_pMemoryMap = nullptr;

    //    ui->tableWidgetSignature->setFont(XAbstractTableView::getMonoFont(10));
    ui->textEditSignature->setFont(XOptions::getMonoFont());

    const bool bBlocked1 = ui->spinBoxCount->blockSignals(true);
    const bool bBlocked2 = ui->comboBoxMethod->blockSignals(true);

    ui->comboBoxMethod->addItem("", 0);
    ui->comboBoxMethod->addItem(tr("Relative virtual address"), 1);

    m_nSymbolWidth = XLineEditHEX::getSymbolWidth(ui->tableWidgetSignature);

    ui->spinBoxCount->blockSignals(bBlocked1);
    ui->comboBoxMethod->blockSignals(bBlocked2);
}

DialogMultiDisasmSignature::~DialogMultiDisasmSignature()
{
    delete ui;
}

void DialogMultiDisasmSignature::adjustView()
{
    getGlobalOptions()->adjustTableWidget(ui->tableWidgetSignature, XOptions::ID_VIEW_FONT_TABLEVIEWS);
}

void DialogMultiDisasmSignature::setData(QIODevice *pDevice, qint64 nOffset, XBinary::_MEMORY_MAP *pMemoryMap, XDisasmCore *pDisasmCore)
{
    this->m_pDevice = pDevice;
    this->m_nOffset = nOffset;
    this->m_pMemoryMap = pMemoryMap;
    this->m_pDisasmCore = pDisasmCore;

    reload();
}

void DialogMultiDisasmSignature::reload()
{
    qint32 nCount = ui->spinBoxCount->value();
    qint32 nMethod = ui->comboBoxMethod->currentData().toInt();

    XDisasmCore::ST st = XDisasmCore::ST_FULL;

    if (nMethod == 1) {
        st = XDisasmCore::ST_REL;
    }

    m_listRecords = m_pDisasmCore->getSignatureRecords(m_pDevice, m_pMemoryMap, m_nOffset, nCount, st);

    qint32 nNumberOfRecords = m_listRecords.count();

    ui->tableWidgetSignature->clear();

    ui->tableWidgetSignature->setColumnCount(5);
    ui->tableWidgetSignature->setRowCount(nNumberOfRecords);

    QStringList listHeaders;
    listHeaders.append(tr("Address"));
    listHeaders.append(tr("Bytes"));
    listHeaders.append(tr("Opcode"));
    listHeaders.append("");
    listHeaders.append("");

    ui->tableWidgetSignature->setHorizontalHeaderLabels(listHeaders);

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        ui->tableWidgetSignature->setItem(i, 0, new QTableWidgetItem(XBinary::valueToHex(m_listRecords.at(i).nAddress)));
        ui->tableWidgetSignature->setItem(i, 1, new QTableWidgetItem(m_listRecords.at(i).baOpcode.toHex().data()));

        if (!m_listRecords.at(i).bIsConst) {
            QPushButton *pUseSignatureButton = new QPushButton(this);
            pUseSignatureButton->setText(m_listRecords.at(i).sOpcode);
            pUseSignatureButton->setCheckable(true);
            connect(pUseSignatureButton, SIGNAL(clicked()), this, SLOT(reloadSignature()));

            ui->tableWidgetSignature->setCellWidget(i, 2, pUseSignatureButton);

            if (m_listRecords.at(i).nDispSize) {
                QPushButton *pDispButton = new QPushButton(this);
                pDispButton->setText(QString("d"));
                pDispButton->setCheckable(true);
                pDispButton->setMaximumWidth(m_nSymbolWidth * 6);
                connect(pDispButton, SIGNAL(clicked()), this, SLOT(reloadSignature()));

                ui->tableWidgetSignature->setCellWidget(i, 3, pDispButton);
            }

            if (m_listRecords.at(i).nImmSize) {
                QPushButton *pImmButton = new QPushButton(this);
                pImmButton->setText(QString("i"));
                pImmButton->setCheckable(true);
                pImmButton->setMaximumWidth(m_nSymbolWidth * 6);
                connect(pImmButton, SIGNAL(clicked()), this, SLOT(reloadSignature()));

                ui->tableWidgetSignature->setCellWidget(i, 4, pImmButton);
            }
        } else {
            ui->tableWidgetSignature->setItem(i, 2, new QTableWidgetItem(m_listRecords.at(i).sOpcode));
        }
    }

    ui->tableWidgetSignature->setColumnWidth(0, m_nSymbolWidth * 12);
    ui->tableWidgetSignature->setColumnWidth(1, m_nSymbolWidth * 20);
    ui->tableWidgetSignature->setColumnWidth(2, m_nSymbolWidth * 20);
    ui->tableWidgetSignature->setColumnWidth(3, m_nSymbolWidth * 6);
    ui->tableWidgetSignature->setColumnWidth(4, m_nSymbolWidth * 6);

    ui->tableWidgetSignature->horizontalHeader()->setVisible(true);

    //    ui->tableWidgetSignature->horizontalHeader()->setSectionResizeMode(0,QHeaderView::Interactive);
    //    ui->tableWidgetSignature->horizontalHeader()->setSectionResizeMode(1,QHeaderView::Stretch);
    //    ui->tableWidgetSignature->horizontalHeader()->setSectionResizeMode(2,QHeaderView::Interactive);
    //    ui->tableWidgetSignature->horizontalHeader()->setSectionResizeMode(3,QHeaderView::Interactive);
    //    ui->tableWidgetSignature->horizontalHeader()->setSectionResizeMode(4,QHeaderView::Interactive);

    reloadSignature();
}

void DialogMultiDisasmSignature::reloadSignature()
{
    QString sText;

    QChar cWild = QChar('.');
    QString _sWild = ui->lineEditWildcard->text();

    if (_sWild.size()) {
        cWild = _sWild.at(0);
    }

    qint32 nNumberOfRecords = m_listRecords.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        bool bUse = true;
        bool bDisp = true;
        bool bImm = true;

        QPushButton *pUseSignatureButton = dynamic_cast<QPushButton *>(ui->tableWidgetSignature->cellWidget(i, 2));
        QPushButton *pDispButton = dynamic_cast<QPushButton *>(ui->tableWidgetSignature->cellWidget(i, 3));
        QPushButton *pImmButton = dynamic_cast<QPushButton *>(ui->tableWidgetSignature->cellWidget(i, 4));

        if (pUseSignatureButton) {
            bUse = !(pUseSignatureButton->isChecked());
        }

        if (pDispButton) {
            pDispButton->setEnabled(bUse);
            bDisp = !(pDispButton->isChecked());
        }

        if (pImmButton) {
            pImmButton->setEnabled(bUse);
            bImm = !(pImmButton->isChecked());
        }

        qint32 nSize = m_listRecords.at(i).baOpcode.size();

        QString sRecord;

        if (bUse) {
            sRecord = m_listRecords.at(i).baOpcode.toHex().data();

            if (!bDisp) {
                sRecord = XDisasmCore::replaceWildChar(sRecord, m_listRecords.at(i).nDispOffset, m_listRecords.at(i).nDispSize, cWild);
            }

            if (!bImm) {
                sRecord = XDisasmCore::replaceWildChar(sRecord, m_listRecords.at(i).nImmOffset, m_listRecords.at(i).nImmSize, cWild);
            }

            if (m_listRecords.at(i).bIsConst) {
                sRecord = XDisasmCore::replaceWildChar(sRecord, m_listRecords.at(i).nImmOffset, m_listRecords.at(i).nImmSize, QChar('$'));
            }
        } else {
            for (qint32 j = 0; j < nSize; j++) {
                sRecord += cWild;
                sRecord += cWild;
            }
        }

        sText += sRecord;
    }

    if (ui->checkBoxUpper->isChecked()) {
        sText = sText.toUpper();
    } else {
        sText = sText.toLower();
    }

    if (ui->checkBoxSpaces->isChecked()) {
        QString _sText;

        qint32 nSize = sText.size();

        for (qint32 i = 0; i < nSize; i++) {
            _sText += sText.at(i);

            if ((i % 2) && (i != (nSize - 1))) {
                _sText += QChar(' ');
            }
        }

        sText = _sText;
    }

    ui->textEditSignature->setText(sText);
}

void DialogMultiDisasmSignature::on_pushButtonOK_clicked()
{
    this->close();
}

void DialogMultiDisasmSignature::on_checkBoxSpaces_toggled(bool bChecked)
{
    Q_UNUSED(bChecked)

    reloadSignature();
}

void DialogMultiDisasmSignature::on_checkBoxUpper_toggled(bool bChecked)
{
    Q_UNUSED(bChecked)

    reloadSignature();
}

void DialogMultiDisasmSignature::on_lineEditWildcard_textChanged(const QString &sText)
{
    Q_UNUSED(sText)

    reloadSignature();
}

void DialogMultiDisasmSignature::on_pushButtonCopy_clicked()
{
    QClipboard *pClipboard = QApplication::clipboard();
    pClipboard->setText(ui->textEditSignature->toPlainText());
}

void DialogMultiDisasmSignature::on_spinBoxCount_valueChanged(int nValue)
{
    Q_UNUSED(nValue)

    reload();
}

void DialogMultiDisasmSignature::on_comboBoxMethod_currentIndexChanged(int nIndex)
{
    Q_UNUSED(nIndex)

    reload();
}

void DialogMultiDisasmSignature::on_pushButtonScan_clicked()
{
    SearchValuesWidget::OPTIONS options = {};
    options.fileType = m_pMemoryMap->fileType;
    options.valueType = XBinary::VT_SIGNATURE;
    options.endian = m_pMemoryMap->endian;
    options.varValue = ui->textEditSignature->toPlainText();
    options.bScan = true;

    DialogSearchValues dialogSearchValues(this);
    dialogSearchValues.setGlobal(getShortcuts(), getGlobalOptions());
    dialogSearchValues.setData(m_pDevice, options);

    dialogSearchValues.exec();
}

void DialogMultiDisasmSignature::registerShortcuts(bool bState)
{
    Q_UNUSED(bState)
}
