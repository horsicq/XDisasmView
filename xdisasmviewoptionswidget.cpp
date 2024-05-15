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
#include "xdisasmviewoptionswidget.h"

#include "ui_xdisasmviewoptionswidget.h"

XDisasmViewOptionsWidget::XDisasmViewOptionsWidget(QWidget *pParent) : QWidget(pParent), ui(new Ui::XDisasmViewOptionsWidget)
{
    ui->setupUi(this);

    g_pOptions = nullptr;
    g_mode = MODE_ALL;

    setProperty("GROUPID", XOptions::GROUPID_DISASM);
}

XDisasmViewOptionsWidget::~XDisasmViewOptionsWidget()
{
    delete ui;
}

void XDisasmViewOptionsWidget::setOptions(XOptions *pOptions, MODE mode)
{
    g_pOptions = pOptions;
    g_mode = mode;

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

void XDisasmViewOptionsWidget::setDefaultValues(XOptions *pOptions, MODE mode)
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

    if ((mode == MODE_ALL) || (mode == MODE_X86)) {
        pOptions->addID(XOptions::ID_DISASM_SYNTAX, "");
    }

    pOptions->addID(XOptions::ID_DISASM_ADDRESSCOLON, true);
    pOptions->addID(XOptions::ID_DISASM_HIGHLIGHT, true);
    pOptions->addID(XOptions::ID_DISASM_UPPERCASE, false);

    // Colors
    pOptions->addID(XOptions::ID_DISASM_COLOR_ARROWS, QString("%1|%2").arg("", ""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_ARROWS_SELECTED, QString("%1|%2").arg(QColor(Qt::red).name(), ""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_REGS, QString("%1|%2").arg(QColor(Qt::red).name(), ""));      // TODO color
    pOptions->addID(XOptions::ID_DISASM_COLOR_NUMBERS, QString("%1|%2").arg(QColor(Qt::blue).name(), ""));  // TODO color
    pOptions->addID(XOptions::ID_DISASM_COLOR_OPCODE, QString("%1|%2").arg(QColor(Qt::blue).name(), ""));
    pOptions->addID(XOptions::ID_DISASM_COLOR_REFS, QString("%1|%2").arg(QColor(Qt::darkGreen).name(), ""));
    // X86
    if ((mode == MODE_ALL) || (mode == MODE_X86)) {
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_REGS_GENERAL, QString("%1|%2").arg(QColor(Qt::red).name(), ""));  // TODO color
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_REGS_STACK, QString("%1|%2").arg(QColor(Qt::red).name(), ""));    // TODO color
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_REGS_SEGMENT, QString("%1|%2").arg(QColor(Qt::red).name(), ""));  // TODO color
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_REGS_DEBUG, QString("%1|%2").arg(QColor(Qt::red).name(), ""));    // TODO color
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_REGS_IP, QString("%1|%2").arg(QColor(Qt::red).name(), ""));       // TODO color
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_REGS_FLAGS, QString("%1|%2").arg(QColor(Qt::red).name(), ""));    // TODO color
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_REGS_FPU, QString("%1|%2").arg(QColor(Qt::red).name(), ""));      // TODO color
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_REGS_XMM, QString("%1|%2").arg(QColor(Qt::red).name(), ""));      // TODO color
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_OPCODE_CALL, QString("%1|%2").arg(QColor(Qt::red).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_OPCODE_RET, QString("%1|%2").arg(QColor(Qt::red).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_OPCODE_NOP, QString("%1|%2").arg(QColor(Qt::gray).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_OPCODE_PUSH, QString("%1|%2").arg(QColor(Qt::blue).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_OPCODE_POP, QString("%1|%2").arg(QColor(Qt::blue).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_OPCODE_COND_JMP, QString("%1|%2").arg(QColor(Qt::green).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_OPCODE_JMP, QString("%1|%2").arg(QColor(Qt::darkBlue).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_OPCODE_INT3, QString("%1|%2").arg(QColor(Qt::darkGray).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_X86_OPCODE_SYSCALL, QString("%1|%2").arg(QColor(Qt::red).name(), ""));
    }

    if ((mode == MODE_ALL) || (mode == MODE_ARM)) {
        // ARM
        pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_REGS_GENERAL, QString("%1|%2").arg(QColor(Qt::red).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_REGS_STACK, QString("%1|%2").arg(QColor(Qt::red).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_OPCODE_B, QString("%1|%2").arg(QColor(Qt::red).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_OPCODE_BL, QString("%1|%2").arg(QColor(Qt::red).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_OPCODE_RET, QString("%1|%2").arg(QColor(Qt::red).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_OPCODE_PUSH, QString("%1|%2").arg(QColor(Qt::blue).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_OPCODE_POP, QString("%1|%2").arg(QColor(Qt::blue).name(), ""));
        pOptions->addID(XOptions::ID_DISASM_COLOR_ARM_OPCODE_NOP, QString("%1|%2").arg(QColor(Qt::gray).name(), ""));
        // TODO more
    }
}

QList<DialogViewColors::RECORD> XDisasmViewOptionsWidget::getRecords(MODE mode)
{
    QList<DialogViewColors::RECORD> listResult;

    {
        QString sGroup = tr("Arrows");

        {
            DialogViewColors::RECORD record = {sGroup, tr("All"), XOptions::ID_DISASM_COLOR_ARROWS};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, tr("Selected"), XOptions::ID_DISASM_COLOR_ARROWS_SELECTED};
            listResult.append(record);
        }
    }
    {
        DialogViewColors::RECORD record = {"", tr("Registers"), XOptions::ID_DISASM_COLOR_REGS};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Numbers"), XOptions::ID_DISASM_COLOR_NUMBERS};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("Opcodes"), XOptions::ID_DISASM_COLOR_OPCODE};
        listResult.append(record);
    }
    {
        DialogViewColors::RECORD record = {"", tr("References"), XOptions::ID_DISASM_COLOR_REFS};
        listResult.append(record);
    }

    // TODO another assemblers
    if ((mode == MODE_ALL) || (mode == MODE_X86)) {
        QString sGroup = "x86/amd64";
        {
            DialogViewColors::RECORD record = {sGroup, tr("General registers"), XOptions::ID_DISASM_COLOR_X86_REGS_GENERAL};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, tr("Stack registers"), XOptions::ID_DISASM_COLOR_X86_REGS_STACK};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, tr("Segment registers"), XOptions::ID_DISASM_COLOR_X86_REGS_SEGMENT};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, tr("Debug registers"), XOptions::ID_DISASM_COLOR_X86_REGS_DEBUG};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, tr("Instruction pointer register"), XOptions::ID_DISASM_COLOR_X86_REGS_IP};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, tr("Flags register"), XOptions::ID_DISASM_COLOR_X86_REGS_FLAGS};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, QString("FPU %1").arg(tr("Registers")), XOptions::ID_DISASM_COLOR_X86_REGS_FPU};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, QString("XMM %1").arg(tr("Registers")), XOptions::ID_DISASM_COLOR_X86_REGS_XMM};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "CALL", XOptions::ID_DISASM_COLOR_X86_OPCODE_CALL};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "RET", XOptions::ID_DISASM_COLOR_X86_OPCODE_RET};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "COND JMP", XOptions::ID_DISASM_COLOR_X86_OPCODE_COND_JMP};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "PUSH", XOptions::ID_DISASM_COLOR_X86_OPCODE_PUSH};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "POP", XOptions::ID_DISASM_COLOR_X86_OPCODE_POP};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "NOP", XOptions::ID_DISASM_COLOR_X86_OPCODE_NOP};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "JMP", XOptions::ID_DISASM_COLOR_X86_OPCODE_JMP};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "INT3", XOptions::ID_DISASM_COLOR_X86_OPCODE_INT3};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "SYSCALL", XOptions::ID_DISASM_COLOR_X86_OPCODE_SYSCALL};
            listResult.append(record);
        }
    }

    if ((mode == MODE_ALL) || (mode == MODE_ARM)) {
        QString sGroup = "arm/arm64";
        {
            DialogViewColors::RECORD record = {sGroup, tr("General registers"), XOptions::ID_DISASM_COLOR_ARM_REGS_GENERAL};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, tr("Stack registers"), XOptions::ID_DISASM_COLOR_ARM_REGS_STACK};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "B", XOptions::ID_DISASM_COLOR_ARM_OPCODE_B};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "BL", XOptions::ID_DISASM_COLOR_ARM_OPCODE_BL};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "RET", XOptions::ID_DISASM_COLOR_ARM_OPCODE_RET};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "PUSH", XOptions::ID_DISASM_COLOR_ARM_OPCODE_PUSH};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "POP", XOptions::ID_DISASM_COLOR_ARM_OPCODE_POP};
            listResult.append(record);
        }
        {
            DialogViewColors::RECORD record = {sGroup, "NOP", XOptions::ID_DISASM_COLOR_ARM_OPCODE_NOP};
            listResult.append(record);
        }
    }
    return listResult;
}

void XDisasmViewOptionsWidget::reload()
{
    g_pOptions->setLineEdit(ui->lineEditDisasmFont, XOptions::ID_DISASM_FONT);
    g_pOptions->setCheckBox(ui->checkBoxDisasmAddressColon, XOptions::ID_DISASM_ADDRESSCOLON);
    g_pOptions->setCheckBox(ui->groupBoxDisasmHighlight, XOptions::ID_DISASM_HIGHLIGHT);
    g_pOptions->setCheckBox(ui->checkBoxDisasmUppercase, XOptions::ID_DISASM_UPPERCASE);

    if ((g_mode == MODE_ALL) || (g_mode == MODE_X86)) {
        g_pOptions->setComboBox(ui->comboBoxDisasmSyntax, XOptions::ID_DISASM_SYNTAX);
    } else {
        ui->groupBoxDisasmSyntax->hide();
    }
}

void XDisasmViewOptionsWidget::on_toolButtonDisasmFont_clicked()
{
    XOptions::handleFontButton(this, ui->lineEditDisasmFont);
}

void XDisasmViewOptionsWidget::on_pushButtonDisasmColors_clicked()
{
    DialogViewColors dialogColors(this);

    QList<DialogViewColors::RECORD> listRecords = getRecords(g_mode);

    dialogColors.setOptions(g_pOptions, listRecords, tr("Colors"));

    dialogColors.exec();
}
