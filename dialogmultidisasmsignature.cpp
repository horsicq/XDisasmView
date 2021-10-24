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
#include "dialogmultidisasmsignature.h"
#include "ui_dialogmultidisasmsignature.h"

DialogMultiDisasmSignature::DialogMultiDisasmSignature(QWidget *pParent) :
    XShortcutsDialog(pParent),
    ui(new Ui::DialogMultiDisasmSignature)
{
    ui->setupUi(this);

//    ui->tableWidgetSignature->setFont(XAbstractTableView::getMonoFont(10));
    ui->textEditSignature->setFont(XAbstractTableView::getMonoFont());

#if QT_VERSION >= QT_VERSION_CHECK(5,3,0)
    const QSignalBlocker signalBlocker1(ui->spinBoxCount);
    const QSignalBlocker signalBlocker2(ui->comboBoxMethod);
#else
    const bool bBlocked1=ui->spinBoxCount->blockSignals(true);
    const bool bBlocked2=ui->comboBoxMethod->blockSignals(true);
#endif

    ui->comboBoxMethod->addItem("",0);
    ui->comboBoxMethod->addItem(tr("Relative virtual address"),1);

    g_nSymbolWidth=XLineEditHEX::getSymbolWidth(ui->tableWidgetSignature);

#if QT_VERSION < QT_VERSION_CHECK(5,3,0)
    ui->spinBoxCount->blockSignals(bBlocked1);
    ui->comboBoxMethod->blockSignals(bBlocked2);
#endif
}

DialogMultiDisasmSignature::~DialogMultiDisasmSignature()
{
    delete ui;
}

void DialogMultiDisasmSignature::setData(QIODevice *pDevice, qint64 nOffset, XBinary::_MEMORY_MAP *pMemoryMap, csh handle, QString sSignaturesPath)
{
    this->g_pDevice=pDevice;
    this->g_nOffset=nOffset;
    this->g_pMemoryMap=pMemoryMap;
    this->g_handle=handle;
    this->g_sSignaturesPath=sSignaturesPath;

    reload();
}

void DialogMultiDisasmSignature::reload()
{
    const qint32 N_X64_OPCODE_SIZE=16;

    g_listRecords.clear();

    bool bStopBranch=false;
    qint32 nCount=ui->spinBoxCount->value();
    qint64 nOffset=g_nOffset;
    qint64 nAddress=XBinary::offsetToAddress(g_pMemoryMap,nOffset);
    qint32 nMethod=ui->comboBoxMethod->currentData().toInt();

    XBinary::DMFAMILY dmFamily=XBinary::getDisasmFamily(g_pMemoryMap);

    for(qint32 i=0;(i<nCount)&&(!bStopBranch);i++)
    {
        if(nOffset!=-1)
        {
            char opcode[N_X64_OPCODE_SIZE];

            XBinary::_zeroMemory(opcode,N_X64_OPCODE_SIZE);

            size_t nDataSize=XBinary::read_array(g_pDevice,nOffset,opcode,N_X64_OPCODE_SIZE);

            uint8_t *pData=(uint8_t *)opcode;

            cs_insn *pInsn=nullptr;
            size_t count=cs_disasm(g_handle,pData,nDataSize,nAddress,1,&pInsn);

            if(count>0)
            {
                if(pInsn->size>1)
                {
                    bStopBranch=!XBinary::isOffsetValid(g_pMemoryMap,nOffset+pInsn->size-1);
                }

                if(!bStopBranch)
                {
                    SIGNATURE_RECORD record={};

                    record.nAddress=nAddress;
                    record.sOpcode=pInsn->mnemonic;
                    QString sArgs=pInsn->op_str;

                    if(sArgs!="")
                    {
                        record.sOpcode+=" "+sArgs;
                    }

                    record.baOpcode=QByteArray(opcode,pInsn->size);

                    // TODO Another archs
                    if(dmFamily==XBinary::DMFAMILY_X86)
                    {
                        record.nDispOffset=pInsn->detail->x86.encoding.disp_offset;
                        record.nDispSize=pInsn->detail->x86.encoding.disp_size;
                        record.nImmOffset=pInsn->detail->x86.encoding.imm_offset;
                        record.nImmSize=pInsn->detail->x86.encoding.imm_size;
                    }

                    nAddress+=pInsn->size;

                    if(nMethod==1)
                    {
                        // TODO another archs !!!
                        if(dmFamily==XBinary::DMFAMILY_X86)
                        {
                            for(qint32 i=0;i<pInsn->detail->x86.op_count;i++)
                            {
                                if(pInsn->detail->x86.operands[i].type==X86_OP_IMM)
                                {
                                    qint64 nImm=pInsn->detail->x86.operands[i].imm;

                                    if(XCapstone::isJmpOpcode(pInsn->id)||XCapstone::isCallOpcode(pInsn->id))
                                    {
                                        nAddress=nImm;
                                        record.bIsConst=true;
                                    }
                                }
                            }
                        }
                        // TODO ARM
                    }

                    g_listRecords.append(record);
                }

                cs_free(pInsn,count);
            }
            else
            {
                bStopBranch=true;
            }
        }

        nOffset=XBinary::addressToOffset(g_pMemoryMap,nAddress);
    }

    int nNumberOfRecords=g_listRecords.count();

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

    for(qint32 i=0;i<nNumberOfRecords;i++)
    {
        ui->tableWidgetSignature->setItem(i,0,new QTableWidgetItem(XBinary::valueToHex(g_listRecords.at(i).nAddress)));
        ui->tableWidgetSignature->setItem(i,1,new QTableWidgetItem(g_listRecords.at(i).baOpcode.toHex().data()));

        if(!g_listRecords.at(i).bIsConst)
        {
            QPushButton *pUseSignatureButton=new QPushButton(this);
            pUseSignatureButton->setText(g_listRecords.at(i).sOpcode);
            pUseSignatureButton->setCheckable(true);
            connect(pUseSignatureButton,SIGNAL(clicked()),this,SLOT(reloadSignature()));

            ui->tableWidgetSignature->setCellWidget(i,2,pUseSignatureButton);

            if(g_listRecords.at(i).nDispSize)
            {
                QPushButton *pDispButton=new QPushButton(this);
                pDispButton->setText(QString("d"));
                pDispButton->setCheckable(true);
                pDispButton->setMaximumWidth(g_nSymbolWidth*6);
                connect(pDispButton,SIGNAL(clicked()),this,SLOT(reloadSignature()));

                ui->tableWidgetSignature->setCellWidget(i,3,pDispButton);
            }

            if(g_listRecords.at(i).nImmSize)
            {
                QPushButton *pImmButton=new QPushButton(this);
                pImmButton->setText(QString("i"));
                pImmButton->setCheckable(true);
                pImmButton->setMaximumWidth(g_nSymbolWidth*6);
                connect(pImmButton,SIGNAL(clicked()),this,SLOT(reloadSignature()));

                ui->tableWidgetSignature->setCellWidget(i,4,pImmButton);
            }
        }
        else
        {
            ui->tableWidgetSignature->setItem(i,2,new QTableWidgetItem(g_listRecords.at(i).sOpcode));
        }
    }

    ui->tableWidgetSignature->setColumnWidth(0,g_nSymbolWidth*12);
    ui->tableWidgetSignature->setColumnWidth(1,g_nSymbolWidth*28);
    ui->tableWidgetSignature->setColumnWidth(2,g_nSymbolWidth*20);
    ui->tableWidgetSignature->setColumnWidth(3,g_nSymbolWidth*6);
    ui->tableWidgetSignature->setColumnWidth(4,g_nSymbolWidth*6);

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

    QChar cWild=QChar('.');
    QString _sWild=ui->lineEditWildcard->text();

    if(_sWild.size())
    {
        cWild=_sWild.at(0);
    }

    qint32 nNumberOfRecords=g_listRecords.count();

    for(qint32 i=0;i<nNumberOfRecords;i++)
    {
        bool bUse=true;
        bool bDisp=true;
        bool bImm=true;

        QPushButton *pUseSignatureButton=dynamic_cast<QPushButton *>(ui->tableWidgetSignature->cellWidget(i,2));
        QPushButton *pDispButton=dynamic_cast<QPushButton *>(ui->tableWidgetSignature->cellWidget(i,3));
        QPushButton *pImmButton=dynamic_cast<QPushButton *>(ui->tableWidgetSignature->cellWidget(i,4));

        if(pUseSignatureButton)
        {
            bUse=!(pUseSignatureButton->isChecked());
        }

        if(pDispButton)
        {
            pDispButton->setEnabled(bUse);
            bDisp=!(pDispButton->isChecked());
        }

        if(pImmButton)
        {
            pImmButton->setEnabled(bUse);
            bImm=!(pImmButton->isChecked());
        }

        int nSize=g_listRecords.at(i).baOpcode.size();

        QString sRecord;

        if(bUse)
        {
            sRecord=g_listRecords.at(i).baOpcode.toHex().data();

            if(!bDisp)
            {
                sRecord=XCapstone::replaceWild(sRecord,g_listRecords.at(i).nDispOffset,g_listRecords.at(i).nDispSize,cWild);
            }

            if(!bImm)
            {
                sRecord=XCapstone::replaceWild(sRecord,g_listRecords.at(i).nImmOffset,g_listRecords.at(i).nImmSize,cWild);
            }

            if(g_listRecords.at(i).bIsConst)
            {
                sRecord=XCapstone::replaceWild(sRecord,g_listRecords.at(i).nImmOffset,g_listRecords.at(i).nImmSize,QChar('$'));
            }
        }
        else
        {
            for(int j=0;j<nSize;j++)
            {
                sRecord+=cWild;
                sRecord+=cWild;
            }
        }

        sText+=sRecord;
    }

    if(ui->checkBoxUpper->isChecked())
    {
        sText=sText.toUpper();
    }
    else
    {
        sText=sText.toLower();
    }

    if(ui->checkBoxSpaces->isChecked())
    {
        QString _sText;

        qint32 nSize=sText.size();

        for(qint32 i=0;i<nSize;i++)
        {
            _sText+=sText.at(i);

            if((i%2)&&(i!=(nSize-1)))
            {
                _sText+=QChar(' ');
            }
        }

        sText=_sText;
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
    QClipboard *clipboard=QApplication::clipboard();
    clipboard->setText(ui->textEditSignature->toPlainText());
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
    SearchSignaturesWidget::OPTIONS options={};
    options.bMenu_Hex=false;
    options.sSignaturesPath=g_sSignaturesPath;
    options.sUserSignature=ui->textEditSignature->toPlainText();

    DialogSearchSignatures dialogSearchSignatures(this);

    dialogSearchSignatures.setData(g_pDevice,g_pMemoryMap->fileType,options,true);
    dialogSearchSignatures.setShortcuts(getShortcuts());

    dialogSearchSignatures.exec();
}
