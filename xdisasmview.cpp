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
    g_handle=0;

    g_nDataSize=0;
    g_nBytesProLine=1;
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

    addColumn((8+2)*getCharWidth(),tr("Address"));
    addColumn((8+2)*getCharWidth(),tr("Offset"));
    addColumn((15*2)*getCharWidth(),tr("Bytes"));
    addColumn(40*getCharWidth(),tr("Opcode"));
}

XDisasmView::~XDisasmView()
{
    if(g_handle)
    {
        cs_close(&g_handle);
    }
}

void XDisasmView::setData(QIODevice *pDevice, XDisasmView::OPTIONS options)
{
    g_pDevice=pDevice;
    g_options=options;

    if(g_options.memoryMap.fileType==XBinary::FT_UNKNOWN)
    {
        XBinary binary(g_pDevice);
        g_options.memoryMap=binary.getMemoryMap();
    }

    setMode(XBinary::DM_X86_16);

    g_nDataSize=pDevice->size();

    qint64 nTotalLineCount=g_nDataSize/g_nBytesProLine;

    if(nTotalLineCount>1)
    {
        nTotalLineCount--;
    }

    setTotalLineCount(nTotalLineCount);

    reload(true);
}

void XDisasmView::setMode(XBinary::DM disasmMode)
{
    g_disasmMode=disasmMode;

    if(g_handle)
    {
        cs_close(&g_handle);
        g_handle=0;
    }

    cs_err error=CS_ERR_HANDLE;

    if      (disasmMode==XBinary::DM_X86_16)        error=cs_open(CS_ARCH_X86,CS_MODE_16,&g_handle);
    else if (disasmMode==XBinary::DM_X86_32)        error=cs_open(CS_ARCH_X86,CS_MODE_32,&g_handle);
    else if (disasmMode==XBinary::DM_X86_64)        error=cs_open(CS_ARCH_X86,CS_MODE_64,&g_handle);
    else if (disasmMode==XBinary::DM_ARM_LE)        error=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_ARM_BE)        error=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_BIG_ENDIAN),&g_handle);

    if(error==CS_ERR_OK)
    {
        cs_option(g_handle,CS_OPT_DETAIL,CS_OPT_ON);
        // TODO Syntax
    }
    else
    {
        g_handle=0;
    }
}

void XDisasmView::goToAddress(qint64 nAddress)
{
    goToOffset(XBinary::addressToOffset(&(g_options.memoryMap),nAddress));
    // TODO reload
}

bool XDisasmView::isOffsetValid(qint64 nOffset)
{
    bool bResult=false;

    if((nOffset>=0)&&(nOffset<g_nDataSize))
    {
        bResult=true;
    }

    return bResult;
}

bool XDisasmView::isEnd(qint64 nOffset)
{
    return (nOffset==g_nDataSize);
}

qint64 XDisasmView::cursorPositionToOffset(XAbstractTableView::CURSOR_POSITION cursorPosition)
{
    qint64 nOffset=-1;

    if((cursorPosition.bIsValid)&&(cursorPosition.ptype==PT_CELL))
    {
        qint64 nBlockOffset=getViewStart()+(cursorPosition.nRow*g_nBytesProLine);

        if(cursorPosition.nColumn==COLUMN_ADDRESS)
        {
            nOffset=nBlockOffset;
        }
        else if(cursorPosition.nColumn==COLUMN_OFFSET)
        {
            nOffset=nBlockOffset;
        }
        else if(cursorPosition.nColumn==COLUMN_BYTES)
        {
            // TODO
            nOffset=nBlockOffset;
        }
        else if(cursorPosition.nColumn==COLUMN_OPCODE)
        {
            nOffset=nBlockOffset;
        }

        if(!isOffsetValid(nOffset))
        {
            nOffset=g_nDataSize; // TODO Check
        }
    }

    return nOffset;
}

void XDisasmView::updateData()
{
    if(g_pDevice)
    {
        qint64 nBlockOffset=getViewStart()*g_nBytesProLine;

        g_listRecords.clear();

        qint32 nNumberLinesProPage=getLinesProPage();

        qint64 nCurrentOffset=nBlockOffset;

        QByteArray baBuffer;
        baBuffer.resize(16); // TODO Check

        for(int i=0;i<nNumberLinesProPage;i++)
        {
            if(nCurrentOffset<g_nDataSize)
            {
                qint32 nBufferSize=qMin(baBuffer.size(),qint32(g_nDataSize-nCurrentOffset));
                qDebug("BufferSize: %d",nBufferSize);
                nBufferSize=XBinary::read_array(g_pDevice,nCurrentOffset,baBuffer.data(),nBufferSize);

                if(nBufferSize==0)
                {
                    break;
                }

                RECORD record={};

                qint64 nCurrentAddress=XBinary::offsetToAddress(&(g_options.memoryMap),nCurrentOffset);

                record.nOffset=nCurrentOffset;
                record.sOffset=QString("%1").arg(nCurrentOffset,8,16,QChar('0')); // TODO address width
                record.sAddress=QString("%1").arg(nCurrentAddress,8,16,QChar('0')); // TODO address width

                if(g_handle)
                {
                    cs_insn *pInsn=0;

                    int nNumberOfOpcodes=cs_disasm(g_handle,(uint8_t *)baBuffer.data(),nBufferSize,nCurrentAddress,1,&pInsn);
                    if(nNumberOfOpcodes>0)
                    {
                        QString sMnemonic=pInsn->mnemonic;
                        QString sStr=pInsn->op_str;

                        record.sDisasm+=sMnemonic;

                        if(sStr!="")
                        {
                            record.sDisasm+=QString(" %1").arg(sStr);
                        }

                        nBufferSize=pInsn->size;

                        cs_free(pInsn, nNumberOfOpcodes);
                    }
                    else
                    {
                        record.sDisasm=tr("Invalid opcode");
                        nBufferSize=1;
                    }
                }
                else
                {
                    nBufferSize=1;
                }

                baBuffer.resize(nBufferSize);
                record.sHEX=baBuffer.toHex().data();

                g_listRecords.append(record);

                nCurrentOffset+=nBufferSize;
            }
        }
    }
}

void XDisasmView::startPainting()
{

}

void XDisasmView::paintColumn(qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{
    Q_UNUSED(nColumn)
    Q_UNUSED(nLeft)
    Q_UNUSED(nTop)
    Q_UNUSED(nWidth)
    Q_UNUSED(nHeight)
}

void XDisasmView::paintCell(qint32 nRow, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{
    qint32 nNumberOfRows=g_listRecords.count();

    if(nRow<nNumberOfRows)
    {
        qint64 nOffset=g_listRecords.at(nRow).nOffset;

        if(isOffsetSelected(nOffset))
        {
            getPainter()->fillRect(nLeft,nTop+getLineDelta(),nWidth,nHeight,viewport()->palette().color(QPalette::Highlight));
        }

        if(nColumn==COLUMN_ADDRESS)
        {
            getPainter()->drawText(nLeft+getCharWidth(),nTop+nHeight,g_listRecords.at(nRow).sAddress); // TODO Text Optional
        }
        else if(nColumn==COLUMN_OFFSET)
        {
            getPainter()->drawText(nLeft+getCharWidth(),nTop+nHeight,g_listRecords.at(nRow).sOffset); // TODO Text Optional
        }
        else if(nColumn==COLUMN_BYTES)
        {
            getPainter()->drawText(nLeft+getCharWidth(),nTop+nHeight,g_listRecords.at(nRow).sHEX); // TODO Text Optional
        }
        else if(nColumn==COLUMN_OPCODE)
        {
            getPainter()->drawText(nLeft+getCharWidth(),nTop+nHeight,g_listRecords.at(nRow).sDisasm); // TODO Text Optional
        }
    }
}

void XDisasmView::endPainting()
{

}

qint64 XDisasmView::getScrollValue()
{
    qint64 nResult=0;

    qint32 nValue=verticalScrollBar()->value();

    qint64 nMaxValue=getMaxScrollValue()*g_nBytesProLine;

    if(g_nDataSize>nMaxValue)
    {
        if(nValue==getMaxScrollValue())
        {
            nResult=g_nDataSize-g_nBytesProLine;
        }
        else
        {
            nResult=((double)nValue/(double)getMaxScrollValue())*g_nDataSize;
        }
    }
    else
    {
        nResult=(qint64)nValue*g_nBytesProLine;
    }

    return nResult;
}

void XDisasmView::setScrollValue(qint64 nOffset)
{
    setViewStart(nOffset);

    qint32 nValue=0;

    if(g_nDataSize>(getMaxScrollValue()*g_nBytesProLine))
    {
        if(nOffset==g_nDataSize-g_nBytesProLine)
        {
            nValue=getMaxScrollValue();
        }
        else
        {
            nValue=((double)(nOffset)/((double)g_nDataSize))*(double)getMaxScrollValue();
        }
    }
    else
    {
        nValue=(nOffset)/g_nBytesProLine;
    }

    verticalScrollBar()->setValue(nValue);

    adjust(true);
}
