// copyright (c) 2020 hors<horsicq@gmail.com>
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
#include "xmultidisasmwidget.h"
#include "ui_xmultidisasmwidget.h"

XMultiDisasmWidget::XMultiDisasmWidget(QWidget *pParent) :
    QWidget(pParent),
    ui(new Ui::XMultiDisasmWidget)
{
    ui->setupUi(this);

    QSignalBlocker blocker(ui->comboBoxMode);

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
    addMode(XBinary::DM_PPC64_LE);
    addMode(XBinary::DM_PPC64_BE);
    addMode(XBinary::DM_SPARC);
    addMode(XBinary::DM_S390X);
    addMode(XBinary::DM_XCORE);
    addMode(XBinary::DM_M68K);
    addMode(XBinary::DM_M68K40);
    addMode(XBinary::DM_TMS320C64X);
}

XMultiDisasmWidget::~XMultiDisasmWidget()
{
    delete ui;
}

void XMultiDisasmWidget::setData(QIODevice *pDevice, XDisasmView::OPTIONS options)
{
    QSignalBlocker blocker(ui->comboBoxMode);

    ui->scrollAreaHex->setData(pDevice,options);

    XBinary::DM disasmMode=ui->scrollAreaHex->getMode();

    int nCount=ui->comboBoxMode->count();

    for(int i=0;i<nCount;i++)
    {
        if(ui->comboBoxMode->itemData(i).toInt()==(int)disasmMode)
        {
            ui->comboBoxMode->setCurrentIndex(i);

            break;
        }
    }
}

void XMultiDisasmWidget::goToAddress(qint64 nAddress)
{
    ui->scrollAreaHex->goToAddress(nAddress);
    ui->scrollAreaHex->reload(true);
}

void XMultiDisasmWidget::addMode(XBinary::DM disasmMode)
{
    ui->comboBoxMode->addItem(XBinary::disasmIdToString(disasmMode),disasmMode);
}

void XMultiDisasmWidget::on_comboBoxMode_currentIndexChanged(int nIndex)
{
    Q_UNUSED(nIndex)

    XBinary::DM disasmMode=(XBinary::DM)(ui->comboBoxMode->currentData().toInt());

    ui->scrollAreaHex->setMode(disasmMode);
    ui->scrollAreaHex->reload(true);
}
