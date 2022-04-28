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

    ui->tableWidgetColors->setColumnCount(6);
    ui->tableWidgetColors->setRowCount(11);

    qint32 nRow=0;
    // TODO another assemblers
    addRecord(nRow++,"x86/amd64","CALL",XOptions::ID_DISASM_COLOR_X86_CALL);
    addRecord(nRow++,"x86/amd64","RET",XOptions::ID_DISASM_COLOR_X86_RET);
    addRecord(nRow++,"x86/amd64","JCC",XOptions::ID_DISASM_COLOR_X86_JCC);
    addRecord(nRow++,"x86/amd64","PUSH",XOptions::ID_DISASM_COLOR_X86_PUSH);
    addRecord(nRow++,"x86/amd64","POP",XOptions::ID_DISASM_COLOR_X86_POP);
    addRecord(nRow++,"x86/amd64","NOP",XOptions::ID_DISASM_COLOR_X86_NOP);
    addRecord(nRow++,"x86/amd64","JMP",XOptions::ID_DISASM_COLOR_X86_JMP);
    addRecord(nRow++,"arm/arm64","BL",XOptions::ID_DISASM_COLOR_ARM_BL);
    addRecord(nRow++,"arm/arm64","RET",XOptions::ID_DISASM_COLOR_ARM_RET);
    addRecord(nRow++,"arm/arm64","PUSH",XOptions::ID_DISASM_COLOR_ARM_PUSH);
    addRecord(nRow++,"arm/arm64","POP",XOptions::ID_DISASM_COLOR_ARM_POP);

//    ui->tableWidgetColors->setColumnWidth(COLUMN_TEXT_COLOR,80);
    ui->tableWidgetColors->setColumnWidth(COLUMN_TEXT_COLOR_REMOVE,20);
//    ui->tableWidgetColors->setColumnWidth(COLUMN_BACKGROUND_COLOR,80);
    ui->tableWidgetColors->setColumnWidth(COLUMN_BACKGROUND_COLOR_REMOVE,20);
}

void DialogXDisasmViewColors::save()
{  
    QMapIterator<XOptions::ID,QString> iter(g_mapColors);

    while(iter.hasNext())
    {
        iter.next();

        XOptions::ID id=iter.key();
        QString sValue=iter.value();

        g_pOptions->setValue(id,sValue);
    }
}

void DialogXDisasmViewColors::on_pushButtonCancel_clicked()
{
    this->close();
}

void DialogXDisasmViewColors::addRecord(qint32 nRow,QString sGroup,QString sText,XOptions::ID id)
{
    QPushButton *pButtonTextColor=new QPushButton;
    pButtonTextColor->setText(tr("Text"));
    pButtonTextColor->setProperty("ROW",nRow);
    pButtonTextColor->setProperty("COLUMN",COLUMN_TEXT_COLOR);
    pButtonTextColor->setProperty("ID",id);

    connect(pButtonTextColor,SIGNAL(clicked(bool)),this,SLOT(pushButtonSlot()));

    ui->tableWidgetColors->setCellWidget(nRow,COLUMN_TEXT_COLOR,pButtonTextColor);

    QPushButton *pButtonTextColorRemove=new QPushButton;
    pButtonTextColorRemove->setText(QString("X"));
    pButtonTextColorRemove->setProperty("ROW",nRow);
    pButtonTextColorRemove->setProperty("COLUMN",COLUMN_TEXT_COLOR_REMOVE);
    pButtonTextColorRemove->setProperty("ID",id);

    connect(pButtonTextColorRemove,SIGNAL(clicked(bool)),this,SLOT(pushButtonSlot()));

    ui->tableWidgetColors->setCellWidget(nRow,COLUMN_TEXT_COLOR_REMOVE,pButtonTextColorRemove);

    QPushButton *pButtonBackgroundColor=new QPushButton;
    pButtonBackgroundColor->setText(tr("Background"));
    pButtonBackgroundColor->setProperty("ROW",nRow);
    pButtonBackgroundColor->setProperty("COLUMN",COLUMN_BACKGROUND_COLOR);
    pButtonBackgroundColor->setProperty("ID",id);

    connect(pButtonBackgroundColor,SIGNAL(clicked(bool)),this,SLOT(pushButtonSlot()));

    ui->tableWidgetColors->setCellWidget(nRow,COLUMN_BACKGROUND_COLOR,pButtonBackgroundColor);

    QPushButton *pButtonBackgroundColorRemove=new QPushButton;
    pButtonBackgroundColorRemove->setText(QString("X"));
    pButtonBackgroundColorRemove->setProperty("ROW",nRow);
    pButtonBackgroundColorRemove->setProperty("COLUMN",COLUMN_BACKGROUND_COLOR_REMOVE);
    pButtonBackgroundColorRemove->setProperty("ID",id);

    connect(pButtonBackgroundColorRemove,SIGNAL(clicked(bool)),this,SLOT(pushButtonSlot()));

    ui->tableWidgetColors->setItem(nRow,COLUMN_GROUP,new QTableWidgetItem(sGroup));

    ui->tableWidgetColors->setCellWidget(nRow,COLUMN_BACKGROUND_COLOR_REMOVE,pButtonBackgroundColorRemove);

    QLineEdit *pLineEdit=new QLineEdit;
    pLineEdit->setText(sText);
    pLineEdit->setProperty("ROW",nRow);
    pLineEdit->setProperty("COLUMN",COLUMN_STRING);
    pLineEdit->setProperty("ID",id);
    pLineEdit->setReadOnly(true);

    ui->tableWidgetColors->setCellWidget(nRow,COLUMN_STRING,pLineEdit);

    g_mapColors.insert(id,g_pOptions->getValue(id).toString());

    updateRow(nRow);
}

void DialogXDisasmViewColors::updateRow(qint32 nRow)
{
    XOptions::ID id=(XOptions::ID)(ui->tableWidgetColors->cellWidget(nRow,COLUMN_TEXT_COLOR)->property("ID").toUInt());

    QString sColor=g_mapColors.value(id);
    QString sTextColor=sColor.section("|",0,0);
    QString sBackgroundColor=sColor.section("|",1,1);

    QLineEdit *pLineEdit=(QLineEdit *)(ui->tableWidgetColors->cellWidget(nRow,COLUMN_STRING));

    pLineEdit->setStyleSheet(QString("color: %1;  background-color: %2").arg(sTextColor,sBackgroundColor));

    ((QPushButton *)(ui->tableWidgetColors->cellWidget(nRow,COLUMN_TEXT_COLOR_REMOVE)))->setEnabled(sTextColor!="");
    ((QPushButton *)(ui->tableWidgetColors->cellWidget(nRow,COLUMN_BACKGROUND_COLOR_REMOVE)))->setEnabled(sBackgroundColor!="");
}

void DialogXDisasmViewColors::on_pushButtonOK_clicked()
{
    save();

    this->close();
}

void DialogXDisasmViewColors::pushButtonSlot()
{
    QPushButton *pPushButton=qobject_cast<QPushButton*>(sender());

    if(pPushButton)
    {
        qint32 nRow=pPushButton->property("ROW").toInt();
        qint32 nColumn=pPushButton->property("COLUMN").toInt();
        XOptions::ID id=(XOptions::ID)(pPushButton->property("ID").toUInt());

        QString sColor=g_mapColors.value(id);
        QString sTextColor=sColor.section("|",0,0);
        QString sBackgroundColor=sColor.section("|",1,1);

        if(nColumn==COLUMN_TEXT_COLOR)
        {
            QColor color;
            color.setNamedColor(sTextColor);

            color=QColorDialog::getColor(color,this,tr("Text"));

            sTextColor=color.name();
        }
        else if(nColumn==COLUMN_BACKGROUND_COLOR)
        {
            QColor color;
            color.setNamedColor(sBackgroundColor);

            color=QColorDialog::getColor(color,this,tr("Background"));

            sBackgroundColor=color.name();
        }
        else if(nColumn==COLUMN_TEXT_COLOR_REMOVE)
        {
            sTextColor="";
        }
        else if(nColumn==COLUMN_BACKGROUND_COLOR_REMOVE)
        {
            sBackgroundColor="";
        }

        if((sTextColor!="")||(sBackgroundColor!=""))
        {
            sColor=QString("%1|%2").arg(sTextColor,sBackgroundColor);
        }
        else
        {
            sColor="";
        }

        g_mapColors.insert(id,sColor);

        updateRow(nRow);
    }
}
