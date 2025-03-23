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
#include "xmultidisasmwidget.h"

#include "ui_xmultidisasmwidget.h"

XMultiDisasmWidget::XMultiDisasmWidget(QWidget *pParent) : XShortcutsWidget(pParent), ui(new Ui::XMultiDisasmWidget)
{
    ui->setupUi(this);

    XOptions::adjustToolButton(ui->toolButtonVisitedNext, XOptions::ICONTYPE_FORWARD, Qt::ToolButtonIconOnly);
    XOptions::adjustToolButton(ui->toolButtonVisitedPrev, XOptions::ICONTYPE_BACKWARD, Qt::ToolButtonIconOnly);

    ui->comboBoxType->setToolTip(tr("Type"));
    ui->comboBoxMode->setToolTip(tr("Mode"));
    ui->toolButtonVisitedNext->setToolTip(tr("Next visited"));
    ui->toolButtonVisitedPrev->setToolTip(tr("Previous visited"));
    ui->checkBoxReadonly->setToolTip(tr("Readonly"));
    ui->comboBoxMethod->setToolTip(tr("Method"));
    ui->comboBoxView->setToolTip(tr("View"));

    g_pDevice = nullptr;
    g_pXInfoDB = nullptr;
    g_options = {};

    // TODO BPF
    // TODO Check more !!!

    connect(ui->scrollAreaDisasm, SIGNAL(followLocation(quint64, qint32, qint64, qint32)), this, SIGNAL(followLocation(quint64, qint32, qint64, qint32)));
    connect(ui->scrollAreaDisasm, SIGNAL(errorMessage(QString)), this, SLOT(errorMessageSlot(QString)));
    //    connect(ui->scrollAreaDisasm,SIGNAL(cursorViewPosChanged(qint64)),this,SLOT(cursorChanged(qint64)));
    //    connect(ui->scrollAreaDisasm,SIGNAL(selectionChanged()),this,SLOT(selectionChanged()));
    connect(ui->scrollAreaDisasm, SIGNAL(currentLocationChanged(quint64, qint32, qint64)), this, SIGNAL(currentLocationChanged(quint64, qint32, qint64)));
    connect(ui->scrollAreaDisasm, SIGNAL(dataChanged(qint64, qint64)), this, SIGNAL(dataChanged(qint64, qint64)));
    connect(ui->scrollAreaDisasm, SIGNAL(deviceSizeChanged(qint64, qint64)), this, SIGNAL(deviceSizeChanged(qint64, qint64)));
    connect(ui->scrollAreaDisasm, SIGNAL(visitedStateChanged()), this, SLOT(adjustVisitedState()));

    setReadonlyVisible(false);
    ui->checkBoxReadonly->setChecked(true);

    adjustVisitedState();

    ui->comboBoxView->addItem(tr("Compact"), XDisasmView::VIEWDISASM_COMPACT);
    ui->comboBoxView->addItem(tr("Full"), XDisasmView::VIEWDISASM_FULL);

    // ui->frameAnalize->hide();
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
        XFormats::setFileTypeComboBox(options.fileType, pDevice, ui->comboBoxType, XBinary::TL_OPTION_EXECUTABLE);
    } else {
        ui->scrollAreaDisasm->setDevice(nullptr, 0, -1);
    }

    adjustVisitedState();

    reloadFileType();
}

void XMultiDisasmWidget::setDevice(QIODevice *pDevice)
{
    ui->scrollAreaDisasm->setDevice(pDevice, 0, -1);
}

void XMultiDisasmWidget::setXInfoDB(XInfoDB *pXInfoDB)
{
    ui->scrollAreaDisasm->setXInfoDB(pXInfoDB);
}

void XMultiDisasmWidget::setLocation(quint64 nLocation, qint32 nLocationType, qint64 nSize)
{
    ui->scrollAreaDisasm->setLocation(nLocation, nLocationType, nSize);
}

void XMultiDisasmWidget::adjustView()
{
    ui->scrollAreaDisasm->adjustView();
}

void XMultiDisasmWidget::setWidgetFocus()
{
    ui->scrollAreaDisasm->setFocus();
}

void XMultiDisasmWidget::reloadData(bool bSaveSelection)
{
    Q_UNUSED(bSaveSelection)
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

void XMultiDisasmWidget::reloadFileType()
{
    if (g_pDevice) {
        g_options.fileType = (XBinary::FT)(ui->comboBoxType->currentData().toInt());

        XDisasmView::OPTIONS options = {};
        options.nInitAddress = g_options.nInitAddress;
        options.nEntryPointAddress = XFormats::getEntryPointAddress(g_options.fileType, g_pDevice);
        options.bMenu_Hex = g_options.bMenu_Hex;
        options.bHideReadOnly = g_options.bHideReadOnly;

        XBinary::FILEFORMATINFO fileFormatInfo = {};

        if (g_options.fileType == XBinary::FT_REGION) {
            fileFormatInfo = XFormats::getFileFormatInfo(g_options.fileType, g_pDevice, true, g_options.nStartAddress);
        } else {
            fileFormatInfo = XFormats::getFileFormatInfo(g_options.fileType, g_pDevice);
        }

        // if (g_options.sArch != "") {
        //     options.memoryMapRegion.sArch = g_options.sArch;
        // }

        ui->comboBoxMode->setEnabled(!g_options.bModeFixed);

        // ui->scrollAreaDisasm->setData(g_pDevice, options);

        XBinary::DM disasmMode = XBinary::getDisasmMode(&fileFormatInfo);

        XFormats::setDisasmModeComboBox(disasmMode, ui->comboBoxMode);

        options.disasmMode = (XBinary::DM)(ui->comboBoxMode->currentData().toInt());

        // // TODO Check
        // if (ui->scrollAreaDisasm->getXInfoDB()) {
        //     ui->scrollAreaDisasm->getXInfoDB()->setData(g_pDevice, options.memoryMapRegion.fileType, options.disasmMode);
        //     //            getSymbols();
        // }

        ui->scrollAreaDisasm->setData(g_pDevice, options);
        ui->scrollAreaDisasm->reload(true);
        reloadMethod();
    }
}

void XMultiDisasmWidget::reloadMethod()
{
    const bool bBlocked1 = ui->comboBoxMethod->blockSignals(true);
    ui->comboBoxMethod->clear();
    ui->comboBoxMethod->addItem("", XDisasmView::VIEWMETHOD_NONE);
    ui->comboBoxMethod->addItem(tr("Analyzed"), XDisasmView::VIEWMETHOD_ANALYZED);

    ui->comboBoxMethod->blockSignals(bBlocked1);
}

void XMultiDisasmWidget::adjustMode()
{
    XDisasmView::OPTIONS options = ui->scrollAreaDisasm->getOptions();
    options.disasmMode = (XBinary::DM)(ui->comboBoxMode->currentData().toInt());

    ui->scrollAreaDisasm->setData(g_pDevice, options);
    ui->scrollAreaDisasm->reload(true);

    // if (ui->scrollAreaDisasm->getXInfoDB()) {
    //     ui->scrollAreaDisasm->getXInfoDB()->setData(g_pDevice, options.memoryMapRegion.fileType, options.disasmMode);
    // }
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

void XMultiDisasmWidget::on_comboBoxMethod_currentIndexChanged(int nIndex)
{
    Q_UNUSED(nIndex)

    ui->scrollAreaDisasm->setViewMethod((XDisasmView::VIEWMETHOD)(ui->comboBoxMethod->currentData().toInt()));
}

void XMultiDisasmWidget::on_comboBoxView_currentIndexChanged(int nIndex)
{
    Q_UNUSED(nIndex)

    ui->scrollAreaDisasm->setViewDisasm((XDisasmView::VIEWDISASM)(ui->comboBoxView->currentData().toInt()));
}
