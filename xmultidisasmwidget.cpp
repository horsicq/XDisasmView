/* Copyright (c) 2020-2023 hors<horsicq@gmail.com>
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

XMultiDisasmWidget::XMultiDisasmWidget(QWidget *pParent) : XShortcutsWidget(pParent), ui(new Ui::XMultiDisasmWidget)
{
    ui->setupUi(this);

    g_pDevice = nullptr;
    g_pXInfoDB = nullptr;
    g_options = {};

    const bool bBlocked1 = ui->comboBoxMode->blockSignals(true);

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

    connect(ui->scrollAreaDisasm, SIGNAL(showOffsetHex(qint64)), this, SIGNAL(showOffsetHex(qint64)));
    connect(ui->scrollAreaDisasm, SIGNAL(errorMessage(QString)), this, SLOT(errorMessageSlot(QString)));
    //    connect(ui->scrollAreaDisasm,SIGNAL(cursorViewOffsetChanged(qint64)),this,SLOT(cursorChanged(qint64)));
    //    connect(ui->scrollAreaDisasm,SIGNAL(selectionChanged()),this,SLOT(selectionChanged()));
    connect(ui->scrollAreaDisasm, SIGNAL(dataChanged(qint64, qint64)), this, SIGNAL(dataChanged(qint64, qint64)));
    connect(ui->scrollAreaDisasm, SIGNAL(visitedStateChanged()), this, SLOT(adjustVisitedState()));

    ui->comboBoxMode->blockSignals(bBlocked1);

    setReadonlyVisible(false);
    ui->checkBoxReadonly->setChecked(true);

    adjustVisitedState();
}

XMultiDisasmWidget::~XMultiDisasmWidget()
{
    delete ui;
}

void XMultiDisasmWidget::setData(QIODevice *pDevice, const OPTIONS &options)
{
    g_pDevice = pDevice;
    g_options = options;

    if (pDevice) {
        XFormats::setFileTypeComboBox(options.fileType, pDevice, ui->comboBoxType);
    } else {
        ui->scrollAreaDisasm->setDevice(nullptr);
    }

    //    if (g_pXInfoDB) {
    //        g_pXInfoDB->setAnalyzed(g_pXInfoDB->isShowRecordsPresent());  // TODO Check mb remove

    //        //        if (!(g_pXInfoDB->isAnalyzed())) {

    //        //            if (QMessageBox::question(this,tr("Information"), tr("Make an analysis of this module?"), QMessageBox::Yes|QMessageBox::No) ==
    //        QMessageBox::Yes) {
    //        //                analyze();
    //        //            }
    //        //        }
    //    }

    adjustVisitedState();

    reloadFileType();
}

void XMultiDisasmWidget::setDevice(QIODevice *pDevice)
{
    ui->scrollAreaDisasm->setDevice(pDevice);
}

void XMultiDisasmWidget::setBackupDevice(QIODevice *pDevice)
{
    ui->scrollAreaDisasm->setBackupDevice(pDevice);
}

void XMultiDisasmWidget::setXInfoDB(XInfoDB *pXInfoDB)
{
    ui->scrollAreaDisasm->setXInfoDB(pXInfoDB);
}

void XMultiDisasmWidget::goToAddress(XADDR nAddress)
{
    ui->scrollAreaDisasm->goToAddress(nAddress);
    ui->scrollAreaDisasm->reload(true);
}

void XMultiDisasmWidget::goToOffset(qint64 nOffset)
{
    ui->scrollAreaDisasm->goToOffset(nOffset);
    ui->scrollAreaDisasm->reload(true);
}

void XMultiDisasmWidget::setGlobal(XShortcuts *pShortcuts, XOptions *pXOptions)
{
    ui->scrollAreaDisasm->setGlobal(pShortcuts, pXOptions);
    XShortcutsWidget::setGlobal(pShortcuts, pXOptions);
}

void XMultiDisasmWidget::setReadonly(bool bState)
{
    ui->scrollAreaDisasm->setReadonly(bState);
}

void XMultiDisasmWidget::setReadonlyVisible(bool bState)
{
    if (bState) {
        ui->checkBoxReadonly->show();
    } else {
        ui->checkBoxReadonly->hide();
    }
}

void XMultiDisasmWidget::setEdited(qint64 nDeviceOffset, qint64 nDeviceSize)
{
    ui->scrollAreaDisasm->setEdited(nDeviceOffset, nDeviceSize);

    //    emit changed();
}

void XMultiDisasmWidget::addMode(XBinary::DM disasmMode)
{
    ui->comboBoxMode->addItem(XBinary::disasmIdToString(disasmMode), disasmMode);
}

void XMultiDisasmWidget::reloadFileType()
{
    if (g_pDevice) {
        const bool bBlocked1 = ui->comboBoxMode->blockSignals(true);

        g_options.fileType = (XBinary::FT)(ui->comboBoxType->currentData().toInt());

        XDisasmView::OPTIONS options = {};
        options.nInitAddress = g_options.nInitAddress;
        options.nEntryPointAddress = XFormats::getEntryPointAddress(g_options.fileType, g_pDevice);
        options.bMenu_Hex = g_options.bMenu_Hex;

        if (g_options.fileType == XBinary::FT_REGION) {
            options.memoryMapRegion = XFormats::getMemoryMap(g_options.fileType, g_pDevice, true, g_options.nStartAddress);
        } else {
            options.memoryMapRegion = XFormats::getMemoryMap(g_options.fileType, g_pDevice);
        }

        if (g_options.sArch != "") {
            options.memoryMapRegion.sArch = g_options.sArch;
        }

        // ui->scrollAreaDisasm->setData(g_pDevice, options);

        XBinary::DM disasmMode = XBinary::getDisasmMode(&options.memoryMapRegion);

        qint32 nCount = ui->comboBoxMode->count();

        for (qint32 i = 0; i < nCount; i++) {
            if (ui->comboBoxMode->itemData(i).toInt() == (int)disasmMode) {
                ui->comboBoxMode->setCurrentIndex(i);

                break;
            }
        }

        // TODO Check
        if (ui->scrollAreaDisasm->getXInfoDB()) {
            ui->scrollAreaDisasm->getXInfoDB()->setData(g_pDevice, options.memoryMapRegion.fileType, options.disasmMode);
            //            getSymbols();
        }

        ui->scrollAreaDisasm->setData(g_pDevice, options);
        ui->scrollAreaDisasm->reload(true);

        ui->comboBoxMode->blockSignals(bBlocked1);
    }
}

void XMultiDisasmWidget::adjustMode()
{
    XDisasmView::OPTIONS options = ui->scrollAreaDisasm->getOptions();
    options.disasmMode = (XBinary::DM)(ui->comboBoxMode->currentData().toInt());

    ui->scrollAreaDisasm->setData(g_pDevice, options);
    ui->scrollAreaDisasm->reload(true);

    if (ui->scrollAreaDisasm->getXInfoDB()) {
        ui->scrollAreaDisasm->getXInfoDB()->setData(g_pDevice, options.memoryMapRegion.fileType, options.disasmMode);
    }
}

void XMultiDisasmWidget::getSymbols()
{
    if (g_pXInfoDB) {
        DialogXInfoDBTransferProcess dialogTransfer(this);
        XInfoDBTransfer::OPTIONS options = {};
        options.pDevice = g_pXInfoDB->getDevice();
        options.fileType = g_pXInfoDB->getFileType();

        dialogTransfer.setData(g_pXInfoDB, XInfoDBTransfer::COMMAND_SYMBOLS, options);

        dialogTransfer.showDialogDelay();
        // TODO mn reload
    }
}

void XMultiDisasmWidget::on_comboBoxMode_currentIndexChanged(int nIndex)
{
    Q_UNUSED(nIndex)

    adjustMode();
}

void XMultiDisasmWidget::registerShortcuts(bool bState)
{
    Q_UNUSED(bState)
}

void XMultiDisasmWidget::on_checkBoxReadonly_toggled(bool bChecked)
{
    ui->scrollAreaDisasm->setReadonly(bChecked);
}

void XMultiDisasmWidget::on_comboBoxType_currentIndexChanged(int nIndex)
{
    Q_UNUSED(nIndex)

    reloadFileType();
}

void XMultiDisasmWidget::adjustVisitedState()
{
    ui->toolButtonVisitedPrev->setEnabled(ui->scrollAreaDisasm->isPrevVisitedAvailable());
    ui->toolButtonVisitedNext->setEnabled(ui->scrollAreaDisasm->isNextVisitedAvailable());
}

void XMultiDisasmWidget::on_toolButtonVisitedPrev_clicked()
{
    ui->scrollAreaDisasm->goToPrevVisited();
}

void XMultiDisasmWidget::on_toolButtonVisitedNext_clicked()
{
    ui->scrollAreaDisasm->goToNextVisited();
}
