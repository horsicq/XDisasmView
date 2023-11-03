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
#include "xdisasmviewoptionswidget.h"

#include "ui_xdisasmviewoptionswidget.h"

XDisasmViewOptionsWidget::XDisasmViewOptionsWidget(QWidget *pParent) : QWidget(pParent), ui(new Ui::XDisasmViewOptionsWidget)
{
    ui->setupUi(this);

    g_pOptions = nullptr;

    setProperty("GROUPID", XOptions::GROUPID_DISASM);
}

XDisasmViewOptionsWidget::~XDisasmViewOptionsWidget()
{
    delete ui;
}

void XDisasmViewOptionsWidget::setOptions(XOptions *pOptions)
{
    g_pOptions = pOptions;

    reload();
}

void XDisasmViewOptionsWidget::save()
{
    g_pOptions->getLineEdit(ui->lineEditDisasmFont, XOptions::ID_DISASM_FONT);
    g_pOptions->getComboBox(ui->comboBoxDisasmSyntax, XOptions::ID_DISASM_SYNTAX);
    g_pOptions->getCheckBox(ui->checkBoxDisasmAddressColon, XOptions::ID_DISASM_ADDRESSCOLON);
    g_pOptions->getCheckBox(ui->checkBoxDisasmUppercase, XOptions::ID_DISASM_UPPERCASE);
    g_pOptions->getCheckBox(ui->groupBoxDisasmHighlight, XOptions::ID_DISASM_HIGHLIGHT);
}

void XDisasmViewOptionsWidget::setDefaultValues(XOptions *pOptions)
{
#ifdef Q_OS_WIN
    pOptions->addID(XOptions::ID_DISASM_FONT, "Courier,10,-1,5,50,0,0,0,0,0");
#endif
#ifdef Q_OS_LINUX
    pOptions->addID(XOptions::ID_DISASM_FONT, "DejaVu Sans Mono,10,-1,5,50,0,0,0,0,0");
#endif
#ifdef Q_OS_MACOS
    pOptions->addID(XOptions::ID_DISASM_FONT, "Menlo,10,-1,5,50,0,0,0,0,0");  // TODO Check
#endif

    pOptions->addID(XOptions::ID_DISASM_SYNTAX, "");
    pOptions->addID(XOptions::ID_DISASM_ADDRESSCOLON, true);
    pOptions->addID(XOptions::ID_DISASM_HIGHLIGHT, true);
    pOptions->addID(XOptions::ID_DISASM_UPPERCASE, false);

    DialogViewColors::setDefaultColorValues(pOptions);
}

void XDisasmViewOptionsWidget::reload()
{
    g_pOptions->setLineEdit(ui->lineEditDisasmFont, XOptions::ID_DISASM_FONT);
    g_pOptions->setComboBox(ui->comboBoxDisasmSyntax, XOptions::ID_DISASM_SYNTAX);
    g_pOptions->setCheckBox(ui->checkBoxDisasmAddressColon, XOptions::ID_DISASM_ADDRESSCOLON);
    g_pOptions->setCheckBox(ui->groupBoxDisasmHighlight, XOptions::ID_DISASM_HIGHLIGHT);
    g_pOptions->setCheckBox(ui->checkBoxDisasmUppercase, XOptions::ID_DISASM_UPPERCASE);
}

void XDisasmViewOptionsWidget::on_toolButtonDisasmFont_clicked()
{
    XOptions::handleFontButton(this, ui->lineEditDisasmFont);
}

void XDisasmViewOptionsWidget::on_pushButtonDisasmColors_clicked()
{
    DialogViewColors dialogColors(this);

    QList<DialogViewColors::RECORD> listRecords;
    qint32 nRow = 0;

    // TODO another assemblers
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", tr("Registers"), XOptions::ID_DISASM_COLOR_X86_REGS};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", tr("General registers"), XOptions::ID_DISASM_COLOR_X86_REGS_GENERAL};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", tr("Segment registers"), XOptions::ID_DISASM_COLOR_X86_REGS_SEGMENT};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", tr("Debug registers"), XOptions::ID_DISASM_COLOR_X86_REGS_DEBUG};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", tr("Opcodes"), XOptions::ID_DISASM_COLOR_X86_OPCODE};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", "CALL", XOptions::ID_DISASM_COLOR_X86_OPCODE_CALL};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", "RET", XOptions::ID_DISASM_COLOR_X86_OPCODE_RET};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", "JCC", XOptions::ID_DISASM_COLOR_X86_OPCODE_JCC};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", "PUSH", XOptions::ID_DISASM_COLOR_X86_OPCODE_PUSH};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", "POP", XOptions::ID_DISASM_COLOR_X86_OPCODE_POP};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", "NOP", XOptions::ID_DISASM_COLOR_X86_OPCODE_NOP};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", "JMP", XOptions::ID_DISASM_COLOR_X86_OPCODE_JMP};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", "INT3", XOptions::ID_DISASM_COLOR_X86_OPCODE_INT3};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "x86/amd64", "SYSCALL", XOptions::ID_DISASM_COLOR_X86_OPCODE_SYSCALL};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "arm/arm64", tr("Registers"), XOptions::ID_DISASM_COLOR_ARM_REGS};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "arm/arm64", tr("General registers"), XOptions::ID_DISASM_COLOR_ARM_REGS_GENERAL};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "arm/arm64", tr("Opcodes"), XOptions::ID_DISASM_COLOR_ARM_OPCODE};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "arm/arm64", "B", XOptions::ID_DISASM_COLOR_ARM_OPCODE_B};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "arm/arm64", "BL", XOptions::ID_DISASM_COLOR_ARM_OPCODE_BL};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "arm/arm64", "RET", XOptions::ID_DISASM_COLOR_ARM_OPCODE_RET};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "arm/arm64", "PUSH", XOptions::ID_DISASM_COLOR_ARM_OPCODE_PUSH};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "arm/arm64", "POP", XOptions::ID_DISASM_COLOR_ARM_OPCODE_POP};
        listRecords.append(record);
    }
    {
        DialogViewColors::RECORD record = {nRow++, "arm/arm64", "NOP", XOptions::ID_DISASM_COLOR_ARM_OPCODE_NOP};
        listRecords.append(record);
    }

    dialogColors.setOptions(g_pOptions, listRecords);

    dialogColors.exec();
}
