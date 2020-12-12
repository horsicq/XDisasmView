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
#ifndef XDISASMVIEW_H
#define XDISASMVIEW_H

#include "xcapstone.h"
#include "xabstracttableview.h"
#include "dialoggotoaddress.h"
#include "dialogsearch.h"
#include "dialogdumpprocess.h"
#include "dialogsearchprocess.h"
#include "dialoghexsignature.h"

class XDisasmView : public XAbstractTableView
{
    Q_OBJECT

public:

    struct OPTIONS
    {
        XBinary::_MEMORY_MAP memoryMap;
    };

    explicit XDisasmView(QWidget *pParent=nullptr);
    ~XDisasmView();
    void setData(QIODevice *pDevice,OPTIONS options={});
    void setMode(XBinary::DM disasmMode);
    void goToAddress(qint64 nAddress);

private:
    enum COLUMN
    {
        COLUMN_ADDRESS=0,
        COLUMN_OFFSET,
        COLUMN_BYTES,
        COLUMN_OPCODE
    };

    struct RECORD
    {
        QString sAddress;
        QString sOffset;
        QString sHEX;
        QString sDisasm;
        qint64 nOffset;
    };

protected:
    virtual bool isOffsetValid(qint64 nOffset);
    virtual bool isEnd(qint64 nOffset);
    virtual qint64 cursorPositionToOffset(CURSOR_POSITION cursorPosition);
    virtual void updateData();
    virtual void startPainting();
    virtual void paintColumn(qint32 nColumn,qint32 nLeft,qint32 nTop,qint32 nWidth,qint32 nHeight);
    virtual void paintCell(qint32 nRow,qint32 nColumn,qint32 nLeft,qint32 nTop,qint32 nWidth,qint32 nHeight);
    virtual void endPainting();
    virtual qint64 getScrollValue();
    virtual void setScrollValue(qint64 nOffset);

private:
    QIODevice *g_pDevice;
    OPTIONS g_options;
    qint64 g_nDataSize;
    qint32 g_nBytesProLine;
    QList<RECORD> g_listRecords;
    XBinary::DM g_disasmMode;
    csh g_handle;
    SearchProcess::SEARCHDATA g_searchData;
    QShortcut *g_scGoToAddress;
    QShortcut *g_scDumpToFile;
    QShortcut *g_scSelectAll;
    QShortcut *g_scCopyAsHex;
    QShortcut *g_scFind;
    QShortcut *g_scFindNext;
    QShortcut *g_scSignature;
};

#endif // XDISASMVIEW_H
