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
#include "xdisasmview.h"

XDisasmView::XDisasmView(QWidget *pParent) : XAbstractTableView(pParent)
{
    g_pDevice=nullptr;

    g_nDataSize=0;
    g_nBytesProLine=16;
    g_nDataBlockSize=0;
    g_searchData={};

    g_scGoToAddress   =new QShortcut(QKeySequence(XShortcuts::GOTOADDRESS),   this,SLOT(_goToAddress()));
    g_scDumpToFile    =new QShortcut(QKeySequence(XShortcuts::DUMPTOFILE),    this,SLOT(_dumpToFile()));
    g_scSelectAll     =new QShortcut(QKeySequence(XShortcuts::SELECTALL),     this,SLOT(_selectAll()));
    g_scCopyAsHex     =new QShortcut(QKeySequence(XShortcuts::COPYASHEX),     this,SLOT(_copyAsHex()));
    g_scFind          =new QShortcut(QKeySequence(XShortcuts::FIND),          this,SLOT(_find()));
    g_scFindNext      =new QShortcut(QKeySequence(XShortcuts::FINDNEXT),      this,SLOT(_findNext()));
    g_scSignature     =new QShortcut(QKeySequence(XShortcuts::SIGNATURE),     this,SLOT(_signature()));

#ifdef Q_OS_WIN
    setTextFont(QFont("Courier",10));
#endif
#ifdef Q_OS_LINUX
    setTextFont(QFont("Monospace",10));
#endif
#ifdef Q_OS_OSX
    setTextFont(QFont("Courier",10)); // TODO Check "Menlo"
#endif

    addColumn((8+2)*getCharWidth(),tr("Address"));              // COLUMN_ADDRESS
    addColumn((8+2)*getCharWidth(),tr("Offset"));               // COLUMN_OFFSET
    addColumn((g_nBytesProLine*3+1)*getCharWidth(),"HEX");      // COLUMN_HEX
    addColumn((g_nBytesProLine+2)*getCharWidth(),tr("Disasm")); // COLUMN_DISASM
}

void XDisasmView::setData(QIODevice *pDevice, XDisasmView::OPTIONS options)
{
    g_pDevice=pDevice;
    g_options=options;

    g_nDataSize=pDevice->size();

    qint64 nTotalLineCount=g_nDataSize/g_nBytesProLine;

    if(g_nDataSize%g_nBytesProLine==0)
    {
        nTotalLineCount--;
    }

    setTotalLineCount(nTotalLineCount);

    reload(true);
}

bool XDisasmView::isOffsetValid(qint64 nOffset)
{
    return false;
}

bool XDisasmView::isEnd(qint64 nOffset)
{
    return false;
}

qint64 XDisasmView::cursorPositionToOffset(XAbstractTableView::CURSOR_POSITION cursorPosition)
{
    return 0;
}

void XDisasmView::updateData()
{

}

void XDisasmView::startPainting()
{

}

void XDisasmView::paintColumn(qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{

}

void XDisasmView::paintCell(qint32 nRow, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{

}

void XDisasmView::endPainting()
{

}

void XDisasmView::goToOffset(qint64 nOffset)
{

}
