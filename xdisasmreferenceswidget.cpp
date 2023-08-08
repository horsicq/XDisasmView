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
#include "xdisasmreferenceswidget.h"
#include "ui_xdisasmreferenceswidget.h"

XDisasmReferencesWidget::XDisasmReferencesWidget(QWidget *pParent) : XShortcutsWidget(pParent), ui(new Ui::XDisasmReferencesWidget)
{
    ui->setupUi(this);

    g_pXInfoDB = nullptr;
    g_nAddress = 0;
    g_pModel = nullptr;
    g_pOldModel = nullptr;
}

XDisasmReferencesWidget::~XDisasmReferencesWidget()
{
    delete ui;
}

void XDisasmReferencesWidget::setData(XInfoDB *pXInfoDB, XADDR nAddress, bool bReload)
{
    g_pXInfoDB = pXInfoDB;
    g_nAddress = nAddress;

    if (bReload) {
        reload();
    }
}

void XDisasmReferencesWidget::reload()
{
    if (g_pXInfoDB) {
        g_pOldModel = g_pModel;

        QList<XInfoDB::REFERENCE> listReferences = g_pXInfoDB->getReferencesForAddress(g_nAddress);

        qint32 nNumberOfRecords = listReferences.count();

        g_pModel = new QStandardItemModel(nNumberOfRecords, __HEADER_COLUMN_size);

        g_pModel->setHeaderData(HEADER_COLUMN_ADDRESS, Qt::Horizontal, tr("Address"));
        g_pModel->setHeaderData(HEADER_COLUMN_CODE, Qt::Horizontal, tr("Code"));

        for (qint32 i = 0; i < nNumberOfRecords; i++) {
            QStandardItem *pItemAddress = new QStandardItem;
            pItemAddress->setText(XBinary::valueToHexEx(listReferences.at(i).nAddress));
            pItemAddress->setData(listReferences.at(i).nAddress, Qt::UserRole + USERROLE_ADDRESS);
            g_pModel->setItem(i, HEADER_COLUMN_ADDRESS, pItemAddress);

            QStandardItem *pItemCode = new QStandardItem;
            pItemCode->setText(listReferences.at(i).sCode);
            g_pModel->setItem(i, HEADER_COLUMN_CODE, pItemCode);
        }

        XOptions::setModelTextAlignment(g_pModel, HEADER_COLUMN_ADDRESS, Qt::AlignRight | Qt::AlignVCenter);
        XOptions::setModelTextAlignment(g_pModel, HEADER_COLUMN_CODE, Qt::AlignLeft | Qt::AlignVCenter);

        ui->tableViewReferences->setModel(g_pModel);

        ui->tableViewReferences->setColumnWidth(0, 120);  // TODO

        connect(ui->tableViewReferences->selectionModel(), SIGNAL(currentRowChanged(QModelIndex, QModelIndex)), this,
                SLOT(onTableView_currentRowChanged(QModelIndex, QModelIndex)));

        deleteOldStandardModel(&g_pOldModel);
    }
}

void XDisasmReferencesWidget::registerShortcuts(bool bState)
{
    Q_UNUSED(bState)
}

void XDisasmReferencesWidget::on_pushButtonSaveSymbols_clicked()
{
    if (g_pModel) {
        XShortcutsWidget::saveTableModel(g_pModel, XBinary::getResultFileName(g_pXInfoDB->getDevice(), QString("%1.txt").arg(tr("Symbols"))));
    }
}

void XDisasmReferencesWidget::onTableView_currentRowChanged(const QModelIndex &current, const QModelIndex &previous)
{
    Q_UNUSED(previous)

    QModelIndex index = ui->tableViewReferences->model()->index(current.row(), 0);

    XADDR nAddress = ui->tableViewReferences->model()->data(index, Qt::UserRole + USERROLE_ADDRESS).toULongLong();

    emit currentAddressChanged(nAddress);
}

void XDisasmReferencesWidget::on_tableViewReferences_clicked(const QModelIndex &index)
{
    QModelIndex _index = ui->tableViewReferences->model()->index(index.row(), 0);

    XADDR nAddress = ui->tableViewReferences->model()->data(_index, Qt::UserRole + USERROLE_ADDRESS).toULongLong();

    emit currentAddressChanged(nAddress);
}
