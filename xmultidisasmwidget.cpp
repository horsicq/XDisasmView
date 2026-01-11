/* Copyright (c) 2020-2026 hors<horsicq@gmail.com>
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

    m_pDevice = nullptr;
    m_pXInfoDB = nullptr;
    m_options = {};

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
    m_pDevice = pDevice;
    m_options = options;

    if (pDevice) {
        XFormats::setFileTypeComboBox(options.fileType, pDevice, ui->comboBoxType, XBinary::TL_OPTION_EXECUTABLE);
    } else {
        XBinaryView::OPTIONS _options = {};
        ui->scrollAreaDisasm->setData(nullptr, _options);
    }

    adjustVisitedState();

    reloadFileType();
}

void XMultiDisasmWidget::setDevice(QIODevice *pDevice)
{
    XBinaryView::OPTIONS _options = {};
    ui->scrollAreaDisasm->setData(pDevice, _options);
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
    if (m_pDevice) {
        m_options.fileType = (XBinary::FT)(ui->comboBoxType->currentData().toInt());

        XBinaryView::OPTIONS options = {};
        options.nInitAddress = m_options.nInitAddress;
        options.nEntryPointAddress = XFormats::getEntryPointAddress(m_options.fileType, m_pDevice);
        options.bMenu_Hex = m_options.bMenu_Hex;
        options.bHideReadOnly = m_options.bHideReadOnly;

        XBinary::FILEFORMATINFO fileFormatInfo = {};

        if (m_options.fileType == XBinary::FT_REGION) {
            fileFormatInfo = XFormats::getFileFormatInfo(m_options.fileType, m_pDevice, true, m_options.nStartAddress);
        } else {
            fileFormatInfo = XFormats::getFileFormatInfo(m_options.fileType, m_pDevice);
        }

        // if (m_options.sArch != "") {
        //     options.memoryMapRegion.sArch = m_options.sArch;
        // }

        ui->comboBoxMode->setEnabled(!m_options.bModeFixed);

        // ui->scrollAreaDisasm->setData(m_pDevice, options);

        XBinary::DM disasmMode = XBinary::getDisasmMode(&fileFormatInfo);

        XFormats::setDisasmModeComboBox(disasmMode, ui->comboBoxMode);

        options.fileType = (XBinary::FT)(ui->comboBoxType->currentData().toInt());
        options.disasmMode = (XBinary::DM)(ui->comboBoxMode->currentData().toInt());

        // // TODO Check
        // if (ui->scrollAreaDisasm->getXInfoDB()) {
        //     ui->scrollAreaDisasm->getXInfoDB()->setData(m_pDevice, options.memoryMapRegion.fileType, options.disasmMode);
        //     //            getSymbols();
        // }

        ui->scrollAreaDisasm->setData(m_pDevice, options);
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
    XBinaryView::OPTIONS options = *(ui->scrollAreaDisasm->getBinaryView()->getOptions());
    options.disasmMode = (XBinary::DM)(ui->comboBoxMode->currentData().toInt());

    ui->scrollAreaDisasm->setData(m_pDevice, options);
    ui->scrollAreaDisasm->reload(true);

    // if (ui->scrollAreaDisasm->getXInfoDB()) {
    //     ui->scrollAreaDisasm->getXInfoDB()->setData(m_pDevice, options.memoryMapRegion.fileType, options.disasmMode);
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
