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

    addColumn((10+2)*getCharWidth(),tr("Address"));
    addColumn((10+2)*getCharWidth(),tr("Offset"));
    addColumn((15*2)*getCharWidth(),tr("Bytes")); // TODO adjust function
    addColumn(40*getCharWidth(),tr("Opcode"));

    g_nAddressWidth=8;
    g_nOpcodeSize=16;
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

    if((g_options.memoryMap.nBaseAddress==0)&&(g_options.memoryMap.listRecords.count()==1))
    {
        setColumnEnabled(COLUMN_OFFSET,false);
    }

    XBinary::DM disasmMode=XBinary::getDisasmMode(&(options.memoryMap));

    setMode(disasmMode);

    g_nDataSize=pDevice->size();

    const QFontMetricsF fm(getTextFont());

    if(XBinary::getModeFromSize(g_nDataSize)==XBinary::MODE_64)
    {
        g_nAddressWidth=16;
        setColumnWidth(COLUMN_ADDRESS,2*getCharWidth()+fm.boundingRect("0000000000000000").width());
        setColumnWidth(COLUMN_OFFSET,2*getCharWidth()+fm.boundingRect("0000000000000000").width());
    }
    else
    {
        g_nAddressWidth=8;
        setColumnWidth(COLUMN_ADDRESS,2*getCharWidth()+fm.boundingRect("00000000").width());
        setColumnWidth(COLUMN_OFFSET,2*getCharWidth()+fm.boundingRect("00000000").width());
    }

    qint64 nTotalLineCount=g_nDataSize/g_nBytesProLine;

    if(nTotalLineCount>1)
    {
        nTotalLineCount--;
    }

    setTotalLineCount(nTotalLineCount);

    if(options.nStartAddress)
    {
        _goToOffset(XBinary::addressToOffset(&(g_options.memoryMap),options.nStartAddress));
    }
    else
    {
        setScrollValue(0);
    }

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

    if      (disasmMode==XBinary::DM_X86_16)        error=cs_open(CS_ARCH_X86,cs_mode(CS_MODE_16),&g_handle);
    else if (disasmMode==XBinary::DM_X86_32)        error=cs_open(CS_ARCH_X86,cs_mode(CS_MODE_32),&g_handle);
    else if (disasmMode==XBinary::DM_X86_64)        error=cs_open(CS_ARCH_X86,cs_mode(CS_MODE_64),&g_handle);
    else if (disasmMode==XBinary::DM_ARM_LE)        error=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_ARM_BE)        error=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_ARM64_LE)      error=cs_open(CS_ARCH_ARM64,cs_mode(CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_ARM64_BE)      error=cs_open(CS_ARCH_ARM64,cs_mode(CS_MODE_ARM|CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_CORTEXM)       error=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_THUMB|CS_MODE_MCLASS),&g_handle);
    else if (disasmMode==XBinary::DM_THUMB_LE)      error=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_THUMB_BE)      error=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_THUMB|CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_MIPS_LE)       error=cs_open(CS_ARCH_MIPS,cs_mode(CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_MIPS_BE)       error=cs_open(CS_ARCH_MIPS,cs_mode(CS_MODE_MIPS32|CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_MIPS64_LE)     error=cs_open(CS_ARCH_MIPS,cs_mode(CS_MODE_MIPS64|CS_MODE_LITTLE_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_MIPS64_BE)     error=cs_open(CS_ARCH_MIPS,cs_mode(CS_MODE_MIPS64|CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_PPC64_LE)      error=cs_open(CS_ARCH_PPC,cs_mode(CS_MODE_64|CS_MODE_LITTLE_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_PPC64_BE)      error=cs_open(CS_ARCH_PPC,cs_mode(CS_MODE_64|CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_SPARC)         error=cs_open(CS_ARCH_SPARC,cs_mode(CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_S390X)         error=cs_open(CS_ARCH_SYSZ,cs_mode(CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_XCORE)         error=cs_open(CS_ARCH_XCORE,cs_mode(CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_M68K)          error=cs_open(CS_ARCH_M68K,cs_mode(CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_M68K40)        error=cs_open(CS_ARCH_M68K,cs_mode(CS_MODE_M68K_040),&g_handle);
    else if (disasmMode==XBinary::DM_TMS320C64X)    error=cs_open(CS_ARCH_TMS320C64X,cs_mode(CS_MODE_BIG_ENDIAN),&g_handle);
    else if (disasmMode==XBinary::DM_M6800)         error=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6800),&g_handle);
    else if (disasmMode==XBinary::DM_M6801)         error=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6801),&g_handle);
    else if (disasmMode==XBinary::DM_M6805)         error=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6805),&g_handle);
    else if (disasmMode==XBinary::DM_M6808)         error=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6808),&g_handle);
    else if (disasmMode==XBinary::DM_M6809)         error=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6809),&g_handle);
    else if (disasmMode==XBinary::DM_M6811)         error=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6811),&g_handle);
    else if (disasmMode==XBinary::DM_CPU12)         error=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_CPU12),&g_handle);
    else if (disasmMode==XBinary::DM_HD6301)        error=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6301),&g_handle);
    else if (disasmMode==XBinary::DM_HD6309)        error=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6309),&g_handle);
    else if (disasmMode==XBinary::DM_HCS08)         error=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_HCS08),&g_handle);
//    else if (disasmMode==XBinary::DM_EVM)           error=cs_open(CS_ARCH_M680X,cs_mode(CS_ARCH_EVM),&g_handle);
//    else if (disasmMode==XBinary::DM_MOS65XX)       error=cs_open(CS_ARCH_M680X,cs_mode(CS_ARCH_MOS65XX),&g_handle);

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

XBinary::DM XDisasmView::getMode()
{
    return g_disasmMode;
}

void XDisasmView::goToAddress(qint64 nAddress)
{
    _goToOffset(XBinary::addressToOffset(&(g_options.memoryMap),nAddress));
    // TODO reload
}

XDisasmView::DISASM_RESULT XDisasmView::_disasm(char *pData, qint32 nDataSize, qint64 nAddress)
{
    DISASM_RESULT result={};

    if(g_handle)
    {
        cs_insn *pInsn=0;

        int nNumberOfOpcodes=cs_disasm(g_handle,(uint8_t *)pData,nDataSize,nAddress,1,&pInsn);
        if(nNumberOfOpcodes>0)
        {
            QString sMnemonic=pInsn->mnemonic;
            QString sStr=pInsn->op_str;

            result.sOpcode+=sMnemonic;

            if(sStr!="")
            {
                result.sOpcode+=QString(" %1").arg(sStr);
            }

            result.nSize=pInsn->size;

            cs_free(pInsn, nNumberOfOpcodes);
        }
        else
        {
            result.sOpcode=tr("Invalid opcode");
            result.nSize=1;
        }
    }
    else
    {
        result.nSize=1;
    }

    return result;
}

qint64 XDisasmView::getDisasmOffset(qint64 nOffset,qint64 nOldOffset)
{
    qint64 nResult=nOffset;

    if(nOffset!=nOldOffset)
    {
        qint64 nStartOffset=nOffset-5*g_nOpcodeSize;
        qint64 nEndOffset=nOffset+5*g_nOpcodeSize;

        nStartOffset=qMax(nStartOffset,(qint64)0);
        nEndOffset=qMin(nEndOffset,g_nDataSize);

        if(nOffset>nOldOffset)
        {
            nStartOffset=qMax(nStartOffset,nOldOffset);
        }

        qint32 nSize=nEndOffset-nStartOffset;

        QByteArray baData=XBinary::read_array(g_pDevice,nStartOffset,nSize);

        nSize=baData.size();

        qint64 _nCurrentOffset=0;

        while(nSize>0)
        {
            qint64 _nOffset=nStartOffset+_nCurrentOffset;

            DISASM_RESULT disasmResult=_disasm(baData.data()+_nCurrentOffset,nSize,_nCurrentOffset);

            if((_nOffset<=nOffset)&&(nOffset<_nOffset+disasmResult.nSize))
            {
                if(_nOffset==nOffset)
                {
                    nResult=_nOffset;
                }
                else
                {
                    if(nOffset>nOldOffset)
                    {
                        nResult=_nOffset+disasmResult.nSize;
                    }
                    else
                    {
                        nResult=_nOffset;
                    }
                }

                break;
            }

            _nCurrentOffset+=disasmResult.nSize;
            nSize-=disasmResult.nSize;
        }
    }

    return nResult;
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
        if(cursorPosition.nRow<g_listRecords.count())
        {
            qint64 nBlockOffset=0;
            nBlockOffset=g_listRecords.at(cursorPosition.nRow).nOffset;
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
        }
        else
        {
            if(!isOffsetValid(nOffset))
            {
                nOffset=g_nDataSize; // TODO Check
            }
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
        baBuffer.resize(g_nOpcodeSize); // TODO Check

        for(int i=0;i<nNumberLinesProPage;i++)
        {
            if(nCurrentOffset<g_nDataSize)
            {
                qint32 nBufferSize=qMin(g_nOpcodeSize,qint32(g_nDataSize-nCurrentOffset));

                nBufferSize=XBinary::read_array(g_pDevice,nCurrentOffset,baBuffer.data(),nBufferSize);

                if(nBufferSize==0)
                {
                    break;
                }

                RECORD record={};

                qint64 nCurrentAddress=XBinary::offsetToAddress(&(g_options.memoryMap),nCurrentOffset);

                record.nOffset=nCurrentOffset;
                record.sOffset=QString("%1").arg(nCurrentOffset,g_nAddressWidth,16,QChar('0'));

                if(nCurrentAddress!=-1)
                {
                    record.sAddress=QString("%1").arg(nCurrentAddress,g_nAddressWidth,16,QChar('0'));
                }

                DISASM_RESULT disasmResult=_disasm(baBuffer.data(),nBufferSize,nCurrentAddress);

                record.sOpcode=disasmResult.sOpcode;
                nBufferSize=disasmResult.nSize;

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
            getPainter()->drawText(nLeft+getCharWidth(),nTop+nHeight,g_listRecords.at(nRow).sOpcode); // TODO Text Optional
        }
    }
}

void XDisasmView::endPainting()
{

}

void XDisasmView::contextMenu(const QPoint &pos)
{
    QAction actionGoToAddress(tr("Go to address"),this);
    actionGoToAddress.setShortcut(QKeySequence(XShortcuts::GOTOADDRESS));
    connect(&actionGoToAddress,SIGNAL(triggered()),this,SLOT(_goToAddress()));

    QAction actionDumpToFile(tr("Dump to file"),this);
    actionDumpToFile.setShortcut(QKeySequence(XShortcuts::DUMPTOFILE));
    connect(&actionDumpToFile,SIGNAL(triggered()),this,SLOT(_dumpToFile()));

    QAction actionSignature(tr("Signature"),this);
    actionSignature.setShortcut(QKeySequence(XShortcuts::SIGNATURE));
    connect(&actionSignature,SIGNAL(triggered()),this,SLOT(_signature()));

    QAction actionFind(tr("Find"),this);
    actionFind.setShortcut(QKeySequence(XShortcuts::FIND));
    connect(&actionFind,SIGNAL(triggered()),this,SLOT(_find()));

    QAction actionFindNext(tr("Find next"),this);
    actionFindNext.setShortcut(QKeySequence(XShortcuts::FINDNEXT));
    connect(&actionFindNext,SIGNAL(triggered()),this,SLOT(_findNext()));

    QAction actionSelectAll(tr("Select all"),this);
    actionSelectAll.setShortcut(QKeySequence(XShortcuts::SELECTALL));
    connect(&actionSelectAll,SIGNAL(triggered()),this,SLOT(_selectAll()));

    QAction actionCopyAsHex(tr("Copy as hex"),this);
    actionCopyAsHex.setShortcut(QKeySequence(XShortcuts::COPYASHEX));
    connect(&actionCopyAsHex,SIGNAL(triggered()),this,SLOT(_copyAsHex()));

    QMenu contextMenu(this);
    QMenu menuSelect(tr("Select"),this);
    QMenu menuCopy(tr("Copy"),this);

    contextMenu.addAction(&actionGoToAddress);
    contextMenu.addAction(&actionFind);
    contextMenu.addAction(&actionFindNext);

    STATE state=getState();

    if(state.nSelectionSize)
    {
        contextMenu.addAction(&actionDumpToFile);
        contextMenu.addAction(&actionSignature);

        menuCopy.addAction(&actionCopyAsHex);
        contextMenu.addMenu(&menuCopy);
    }

    menuSelect.addAction(&actionSelectAll);
    contextMenu.addMenu(&menuSelect);

    // TODO reset select

    contextMenu.exec(pos);
}

void XDisasmView::wheelEvent(QWheelEvent *pEvent)
{
    XAbstractTableView::wheelEvent(pEvent);
}

void XDisasmView::keyPressEvent(QKeyEvent *pEvent)
{
    XAbstractTableView::keyPressEvent(pEvent);
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


    qint64 _nResult=getDisasmOffset(nResult,getViewStart());

    if(_nResult!=nResult)
    {
        nResult=_nResult;

        setScrollValue(nResult);
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

void XDisasmView::_goToAddress()
{
    DialogGoToAddress da(this,&(g_options.memoryMap),DialogGoToAddress::TYPE_ADDRESS);
    if(da.exec()==QDialog::Accepted)
    {
        goToAddress(da.getValue());
        setFocus();
        viewport()->update();
    }
}

void XDisasmView::_dumpToFile()
{
    QString sFilter;
    sFilter+=QString("%1 (*.bin)").arg(tr("Raw data"));
    QString sSaveFileName="dump.bin"; // TODO a function
    QString sFileName=QFileDialog::getSaveFileName(this,tr("Save dump"),sSaveFileName,sFilter);

    if(!sFileName.isEmpty())
    {
        STATE state=getState();

        DialogDumpProcess dd(this,g_pDevice,state.nSelectionOffset,state.nSelectionSize,sFileName,DumpProcess::DT_OFFSET);

        dd.exec();
    }
}

void XDisasmView::_signature()
{
    STATE state=getState();

    DialogHexSignature dsh(this,g_pDevice,state.nSelectionOffset,state.nSelectionSize);

    dsh.exec();
}

void XDisasmView::_find()
{
    STATE state=getState();

    g_searchData={};
    g_searchData.nResult=-1;
    g_searchData.nCurrentOffset=state.nCursorOffset;

    DialogSearch dialogSearch(this,g_pDevice,&g_searchData);

    if(dialogSearch.exec()==QDialog::Accepted)
    {
        _goToOffset(g_searchData.nResult);
        setFocus();
        viewport()->update();
    }
}

void XDisasmView::_findNext()
{
    if(g_searchData.bInit)
    {
        g_searchData.nCurrentOffset=g_searchData.nResult+1;
        g_searchData.startFrom=SearchProcess::SF_CURRENTOFFSET;

        DialogSearchProcess dialogSearch(this,g_pDevice,&g_searchData);

        if(dialogSearch.exec()==QDialog::Accepted)
        {
            _goToOffset(g_searchData.nResult);
            setFocus();
            viewport()->update();
        }
    }
}

void XDisasmView::_selectAll()
{
    setSelection(0,g_nDataSize);
}

void XDisasmView::_copyAsHex()
{
    STATE state=getState();

    qint64 nSize=qMin(state.nSelectionSize,(qint64)0x10000);

    QByteArray baData=XBinary::read_array(g_pDevice,state.nSelectionOffset,nSize);

    QApplication::clipboard()->setText(baData.toHex());
}
