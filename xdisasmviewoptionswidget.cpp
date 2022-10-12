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

    setProperty("GROUPID",XOptions::GROUPID_DISASM);
}

XDisasmViewOptionsWidget::~XDisasmViewOptionsWidget()
{
    delete ui;
}

void XDisasmViewOptionsWidget::setOptions(XOptions *pOptions)
{
    g_pOptions=pOptions;

    reload();
}

void XDisasmViewOptionsWidget::save()
{
    g_pOptions->getLineEdit(ui->lineEditDisasmFont,XOptions::ID_DISASM_FONT);
    g_pOptions->getComboBox(ui->comboBoxDisasmSyntax,XOptions::ID_DISASM_SYNTAX);
    g_pOptions->getCheckBox(ui->checkBoxDisasmAddressColon,XOptions::ID_DISASM_ADDRESSCOLON);
    g_pOptions->getCheckBox(ui->checkBoxDisasmUppercase,XOptions::ID_DISASM_UPPERCASE);
    g_pOptions->getCheckBox(ui->groupBoxDisasmHighlight,XOptions::ID_DISASM_HIGHLIGHT);
}

void XDisasmViewOptionsWidget::setDefaultValues(XOptions *pOptions)
{
#ifdef Q_OS_WIN
    pOptions->addID(XOptions::ID_DISASM_FONT,"Courier,10,-1,5,50,0,0,0,0,0");
#endif
#ifdef Q_OS_LINUX
    pOptions->addID(XOptions::ID_DISASM_FONT,"DejaVu Sans Mono,10,-1,5,50,0,0,0,0,0");
#endif
#ifdef Q_OS_MACOS
    pOptions->addID(XOptions::ID_DISASM_FONT,"Menlo,10,-1,5,50,0,0,0,0,0"); // TODO Check
#endif

    pOptions->addID(XOptions::ID_DISASM_SYNTAX,"");
    pOptions->addID(XOptions::ID_DISASM_ADDRESSCOLON,true);
    pOptions->addID(XOptions::ID_DISASM_HIGHLIGHT,true);
    pOptions->addID(XOptions::ID_DISASM_UPPERCASE,false);

    setDefaultColorValues(pOptions);
}

void XDisasmViewOptionsWidget::setDefaultColorValues(XOptions *pOptions)
{
    // Colors
    // X86
    pOptions->addID(XOptions::ID_DISASM_COLOR_X86_CALL,QString("%1|%2").arg(QColor(Qt::red).name(),""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_X86_RET,QString("%1|%2").arg(QColor(Qt::red).name(),""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_X86_NOP,QString("%1|%2").arg(QColor(Qt::gray).name(),""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_X86_PUSH,QString("%1|%2").arg(QColor(Qt::blue).name(),""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_X86_POP,QString("%1|%2").arg(QColor(Qt::blue).name(),""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_X86_JCC,QString("%1|%2").arg(QColor(Qt::green).name(),""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_X86_JMP,QString("%1|%2").arg(QColor(Qt::darkBlue).name(),""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_X86_INT3,QString("%1|%2").arg(QColor(Qt::darkGray).name(),""));
    // ARM
    pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_BL,QString("%1|%2").arg(QColor(Qt::red).name(),""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_RET,QString("%1|%2").arg(QColor(Qt::red).name(),""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_PUSH,QString("%1|%2").arg(QColor(Qt::blue).name(),""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_POP,QString("%1|%2").arg(QColor(Qt::blue).name(),""));
    // TODO more
}

void XDisasmViewOptionsWidget::reload()
{
    g_pOptions->setLineEdit(ui->lineEditDisasmFont,XOptions::ID_DISASM_FONT);
    g_pOptions->setComboBox(ui->comboBoxDisasmSyntax,XOptions::ID_DISASM_SYNTAX);
    g_pOptions->setCheckBox(ui->checkBoxDisasmAddressColon,XOptions::ID_DISASM_ADDRESSCOLON);
    g_pOptions->setCheckBox(ui->groupBoxDisasmHighlight,XOptions::ID_DISASM_HIGHLIGHT);
    g_pOptions->setCheckBox(ui->checkBoxDisasmUppercase,XOptions::ID_DISASM_UPPERCASE);
}

void XDisasmViewOptionsWidget::on_toolButtonDisasmFont_clicked()
{
    XOptions::handleFontButton(this,ui->lineEditDisasmFont);
}

void XDisasmViewOptionsWidget::on_pushButtonDisasmColors_clicked()
{
    DialogXDisasmViewColors dialogColors(this);

    dialogColors.setOptions(g_pOptions);

    dialogColors.exec();
}
