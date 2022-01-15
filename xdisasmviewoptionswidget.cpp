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
#include "xdisasmviewoptionswidget.h"
#include "ui_xdisasmviewoptionswidget.h"

XDisasmViewOptionsWidget::XDisasmViewOptionsWidget(QWidget *pParent) :
    QWidget(pParent),
    ui(new Ui::XDisasmViewOptionsWidget)
{
    ui->setupUi(this);

    g_pOptions=nullptr;
}

XDisasmViewOptionsWidget::~XDisasmViewOptionsWidget()
{
    delete ui;
}

void XDisasmViewOptionsWidget::setOptions(XOptions *pOptions)
{
    g_pOptions=pOptions;

    g_pOptions->setLineEdit(ui->lineEditDisasmFont,XOptions::ID_DISASM_FONT);
}

void XDisasmViewOptionsWidget::save()
{
    g_pOptions->getLineEdit(ui->lineEditDisasmFont,XOptions::ID_DISASM_FONT);
}

void XDisasmViewOptionsWidget::setDefaultValues(XOptions *pOptions)
{
#ifdef Q_OS_WIN
    pOptions->addID(XOptions::ID_DISASM_FONT,"Courier,10,-1,5,50,0,0,0,0,0");
#endif
#ifdef Q_OS_LINUX
    pOptions->addID(XOptions::ID_DISASM_FONT,"Monospace,10,-1,5,50,0,0,0,0,0");
#endif
#ifdef Q_OS_OSX
    pOptions->addID(XOptions::ID_DISASM_FONT,"Menlo,10,-1,5,50,0,0,0,0,0"); // TODO Check
#endif
}

void XDisasmViewOptionsWidget::on_toolButtonDisasmFont_clicked()
{
    QFont _font;
    _font.fromString(ui->lineEditDisasmFont->text());

    bool bOK=false;
    _font=QFontDialog::getFont(&bOK,_font,this);

    if(bOK)
    {
        ui->lineEditDisasmFont->setText(_font.toString());
    }
}

