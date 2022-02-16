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
#include "dialogxdisasmviewcolors.h"
#include "ui_dialogxdisasmviewcolors.h"

DialogXDisasmViewColors::DialogXDisasmViewColors(QWidget *pParent) :
    QDialog(pParent),
    ui(new Ui::DialogXDisasmViewColors)
{
    ui->setupUi(this);
}

DialogXDisasmViewColors::~DialogXDisasmViewColors()
{
    delete ui;
}

void DialogXDisasmViewColors::setOptions(XOptions *pOptions)
{
    g_pOptions=pOptions;

    ui->tableWidgetColors->setColumnCount(5);
    ui->tableWidgetColors->setRowCount(7);

    // TODO another assemblers
    addRecord(0,"CALL",XOptions::ID_DISASM_COLOR_CALL);
    addRecord(1,"RET",XOptions::ID_DISASM_COLOR_RET);
    addRecord(2,"JCC",XOptions::ID_DISASM_COLOR_JCC);
    addRecord(3,"PUSH",XOptions::ID_DISASM_COLOR_PUSH);
    addRecord(4,"POP",XOptions::ID_DISASM_COLOR_POP);
    addRecord(5,"NOP",XOptions::ID_DISASM_COLOR_NOP);
    addRecord(6,"JMP",XOptions::ID_DISASM_COLOR_JMP);

//    ui->tableWidgetColors->setColumnWidth(COLUMN_TEXT_COLOR,80);
    ui->tableWidgetColors->setColumnWidth(COLUMN_TEXT_COLOR_REMOVE,20);
//    ui->tableWidgetColors->setColumnWidth(COLUMN_BACKGROUND_COLOR,80);
    ui->tableWidgetColors->setColumnWidth(COLUMN_BACKGROUND_COLOR_REMOVE,20);
}

void DialogXDisasmViewColors::save()
{
    // TODO
}

void DialogXDisasmViewColors::on_pushButtonCancel_clicked()
{
    this->close();
}

void DialogXDisasmViewColors::addRecord(qint32 nRow,QString sText,XOptions::ID id)
{
    QToolButton *pButtonTextColor=new QToolButton;
    pButtonTextColor->setText(tr("Text"));
    pButtonTextColor->setProperty("ROW",nRow);
    pButtonTextColor->setProperty("COLUMN",COLUMN_TEXT_COLOR);
    pButtonTextColor->setProperty("ID",id);

    ui->tableWidgetColors->setCellWidget(nRow,COLUMN_TEXT_COLOR,pButtonTextColor);

    QToolButton *pButtonTextColorRemove=new QToolButton;
    pButtonTextColorRemove->setText(QString("X"));
    pButtonTextColorRemove->setProperty("ROW",nRow);
    pButtonTextColorRemove->setProperty("COLUMN",COLUMN_TEXT_COLOR_REMOVE);
    pButtonTextColorRemove->setProperty("ID",id);

    ui->tableWidgetColors->setCellWidget(nRow,COLUMN_TEXT_COLOR_REMOVE,pButtonTextColorRemove);

    QToolButton *pButtonBackgroundColor=new QToolButton;
    pButtonBackgroundColor->setText(tr("Background"));
    pButtonBackgroundColor->setProperty("ROW",nRow);
    pButtonBackgroundColor->setProperty("COLUMN",COLUMN_BACKGROUND_COLOR);
    pButtonBackgroundColor->setProperty("ID",id);

    ui->tableWidgetColors->setCellWidget(nRow,COLUMN_BACKGROUND_COLOR,pButtonBackgroundColor);

    QToolButton *pButtonBackgroundColorRemove=new QToolButton;
    pButtonBackgroundColorRemove->setText(QString("X"));
    pButtonBackgroundColorRemove->setProperty("ROW",nRow);
    pButtonBackgroundColorRemove->setProperty("COLUMN",COLUMN_BACKGROUND_COLOR_REMOVE);
    pButtonBackgroundColorRemove->setProperty("ID",id);

    ui->tableWidgetColors->setCellWidget(nRow,COLUMN_BACKGROUND_COLOR_REMOVE,pButtonBackgroundColorRemove);

    QLineEdit *pLineEdit=new QLineEdit;
    pLineEdit->setText(sText);
    pLineEdit->setProperty("ROW",nRow);
    pLineEdit->setProperty("COLUMN",COLUMN_STRING);
    pLineEdit->setProperty("ID",id);
    pLineEdit->setReadOnly(true);

    ui->tableWidgetColors->setCellWidget(nRow,COLUMN_STRING,pLineEdit);

    g_mapColors.insert(id,g_pOptions->getValue(id).toString());

    updateRecord(nRow);
}

void DialogXDisasmViewColors::updateRecord(qint32 nRow)
{
    XOptions::ID id=(XOptions::ID)(ui->tableWidgetColors->cellWidget(nRow,COLUMN_TEXT_COLOR)->property("ID").toUInt());

    QString sColor=g_mapColors.value(id);
    QString sTextColor=sColor.section("|",0,0);
    QString sBackgroundColor=sColor.section("|",1,1);

    QLineEdit *pLineEdit=(QLineEdit *)(ui->tableWidgetColors->cellWidget(nRow,COLUMN_STRING));

    pLineEdit->setStyleSheet(QString("color: %1;  background-color: %2").arg(sTextColor,sBackgroundColor));

    // TODO if no color disable button
}

void DialogXDisasmViewColors::on_pushButtonOK_clicked()
{
    save();

    this->close();
}
