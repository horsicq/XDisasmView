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
#include "xmultidisasmwidget.h"
#include "ui_xmultidisasmwidget.h"

XMultiDisasmWidget::XMultiDisasmWidget(QWidget *pParent) :
    XShortcutsWidget(pParent),
    ui(new Ui::XMultiDisasmWidget)
{
    ui->setupUi(this);

    g_pDevice=nullptr;
    g_options={};

#if QT_VERSION >= QT_VERSION_CHECK(5,3,0)
    const QSignalBlocker blocker1(ui->comboBoxMode);
#else
    const bool bBlocked1=ui->comboBoxMode->blockSignals(true);
#endif

    addMode(XBinary::DM_X86_16);
    addMode(XBinary::DM_X86_32);
    addMode(XBinary::DM_X86_64);
    addMode(XBinary::DM_ARM_LE);
    addMode(XBinary::DM_ARM_BE);
    addMode(XBinary::DM_ARM64_LE);
    addMode(XBinary::DM_ARM64_BE);
    addMode(XBinary::DM_CORTEXM);
    addMode(XBinary::DM_THUMB_LE);
    addMode(XBinary::DM_THUMB_BE);
    addMode(XBinary::DM_MIPS_LE);
    addMode(XBinary::DM_MIPS_BE);
    addMode(XBinary::DM_MIPS64_LE);
    addMode(XBinary::DM_MIPS64_BE);
    addMode(XBinary::DM_PPC_LE);
    addMode(XBinary::DM_PPC_BE);
    addMode(XBinary::DM_PPC64_LE);
    addMode(XBinary::DM_PPC64_BE);
    addMode(XBinary::DM_SPARC);
    addMode(XBinary::DM_S390X);
    addMode(XBinary::DM_XCORE);
    addMode(XBinary::DM_M68K);
    addMode(XBinary::DM_M68K40);
    addMode(XBinary::DM_TMS320C64X);
    addMode(XBinary::DM_M6800);
    addMode(XBinary::DM_M6801);
    addMode(XBinary::DM_M6805);
    addMode(XBinary::DM_M6808);
    addMode(XBinary::DM_M6809);
    addMode(XBinary::DM_M6811);
    addMode(XBinary::DM_CPU12);
    addMode(XBinary::DM_HD6301);
    addMode(XBinary::DM_HD6309);
    addMode(XBinary::DM_HCS08);
    addMode(XBinary::DM_EVM);
    addMode(XBinary::DM_MOS65XX);
    addMode(XBinary::DM_RISKV32);
    addMode(XBinary::DM_RISKV64);
    addMode(XBinary::DM_RISKVC);
    addMode(XBinary::DM_MOS65XX);
    addMode(XBinary::DM_WASM);
    // TODO BPF
    // TODO Check more !!!

    connect(ui->scrollAreaDisasm,SIGNAL(errorMessage(QString)),this,SLOT(errorMessageSlot(QString)));

#if QT_VERSION < QT_VERSION_CHECK(5,3,0)
    ui->comboBoxMode->blockSignals(bBlocked1);
#endif
}

XMultiDisasmWidget::~XMultiDisasmWidget()
{
    delete ui;
}

void XMultiDisasmWidget::setData(QIODevice *pDevice,OPTIONS options)
{ 
    g_pDevice=pDevice;
    g_options=options;

    XFormats::setFileTypeComboBox(options.fileType,g_pDevice,ui->comboBoxType);

    reloadFileType();
}

void XMultiDisasmWidget::goToAddress(XADDR nAddress)
{
    ui->scrollAreaDisasm->goToAddress(nAddress);
    ui->scrollAreaDisasm->reload(true);
}

void XMultiDisasmWidget::setCurrentIPAddress(XADDR nAddress)
{
    ui->scrollAreaDisasm->setCurrentPointerAddress(nAddress);
    ui->scrollAreaDisasm->goToAddress(nAddress);
    ui->scrollAreaDisasm->reload(true);
}

void XMultiDisasmWidget::goToOffset(qint64 nOffset)
{
    ui->scrollAreaDisasm->goToOffset(nOffset);
    ui->scrollAreaDisasm->reload(true);
}

void XMultiDisasmWidget::setGlobal(XShortcuts *pShortcuts,XOptions *pXOptions)
{
    ui->scrollAreaDisasm->setGlobal(pShortcuts,pXOptions);
    XShortcutsWidget::setGlobal(pShortcuts,pXOptions);
}

void XMultiDisasmWidget::setReadonly(bool bState)
{
    ui->scrollAreaDisasm->setReadonly(bState);
}

void XMultiDisasmWidget::setEdited(bool bState)
{
    ui->scrollAreaDisasm->setEdited();

//    emit changed();
}

void XMultiDisasmWidget::addMode(XBinary::DM disasmMode)
{
    ui->comboBoxMode->addItem(XBinary::disasmIdToString(disasmMode),disasmMode);
}

void XMultiDisasmWidget::reloadFileType()
{
#if QT_VERSION >= QT_VERSION_CHECK(5,3,0)
    const QSignalBlocker blocker1(ui->comboBoxMode);
#else
    const bool bBlocked1=ui->comboBoxMode->blockSignals(true);
#endif

    XBinary::FT fileType=(XBinary::FT)(ui->comboBoxType->currentData().toInt());

    XDisasmView::OPTIONS options={};
    options.nInitAddress=g_options.nInitAddress;
    options.nEntryPointAddress=XFormats::getEntryPointAddress(fileType,g_pDevice);

    if(fileType==XBinary::FT_REGION)
    {
        options.memoryMap=XFormats::getMemoryMap(fileType,g_pDevice,true,g_options.nStartAddress);
    }
    else
    {
        options.memoryMap=XFormats::getMemoryMap(fileType,g_pDevice);
    }

    if(g_options.sArch!="")
    {
        options.memoryMap.sArch=g_options.sArch;
    }

    ui->scrollAreaDisasm->setData(g_pDevice,options);

    XBinary::DM disasmMode=ui->scrollAreaDisasm->getMode();

    qint32 nCount=ui->comboBoxMode->count();

    for(qint32 i=0;i<nCount;i++)
    {
        if(ui->comboBoxMode->itemData(i).toInt()==(int)disasmMode)
        {
            ui->comboBoxMode->setCurrentIndex(i);

            break;
        }
    }

    adjustMode();

#if QT_VERSION < QT_VERSION_CHECK(5,3,0)
    ui->comboBoxMode->blockSignals(bBlocked1);
#endif
}

void XMultiDisasmWidget::adjustMode()
{
    XBinary::DM disasmMode=(XBinary::DM)(ui->comboBoxMode->currentData().toInt());

    ui->scrollAreaDisasm->setMode(disasmMode);
    ui->scrollAreaDisasm->reload(true);
}

void XMultiDisasmWidget::on_comboBoxType_currentIndexChanged(int nIndex)
{
    Q_UNUSED(nIndex)

    reloadFileType();
}

void XMultiDisasmWidget::on_comboBoxMode_currentIndexChanged(int nIndex)
{
    Q_UNUSED(nIndex)

    adjustMode();
}

void XMultiDisasmWidget::errorMessageSlot(QString sErrorMessage)
{
    QMessageBox::critical(XOptions::getMainWidget(this),tr("Error"),sErrorMessage);
}

void XMultiDisasmWidget::registerShortcuts(bool bState)
{
    Q_UNUSED(bState)
}
