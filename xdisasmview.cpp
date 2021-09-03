// copyright (c) 2020-2021 hors<horsicq@gmail.com>
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
#include "xdisasmview.h"

XDisasmView::XDisasmView(QWidget *pParent) : XDeviceTableView(pParent)
{
    g_handle=0;

    g_nBytesProLine=1;

    g_scGoToAddress=nullptr;
    g_scGoToOffset=nullptr;
    g_scGoToEntryPoint=nullptr;
    g_scDumpToFile=nullptr;
    g_scSelectAll=nullptr;
    g_scCopyAsHex=nullptr;
    g_scCopyCursorOffset=nullptr;
    g_scCopyCursorAddress=nullptr;
    g_scFind=nullptr;
    g_scFindNext=nullptr;
    g_scHexSignature=nullptr;
    g_scSignature=nullptr;
    g_scHex=nullptr;

    addColumn(tr("Address"),0,true);
    addColumn(tr("Offset"));
    addColumn(tr("Bytes"));
    addColumn(tr("Opcode"));
    addColumn(tr("Comment"));

    setLastColumnScretch(true);

    g_nAddressWidth=8;
    g_nOpcodeSize=16;

    setTextFont(getMonoFont());

    setAddressMode(MODE_ADDRESS);

    g_nCurrentIP=-1;
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
    g_options=options;

    setDevice(pDevice);
    setMemoryMap(g_options.memoryMap);
    setSignaturesPath(g_options.sSignaturesPath);

    XBinary::DM disasmMode=XBinary::getDisasmMode(getMemoryMap());

    setMode(disasmMode);

    adjustColumns();

    qint64 nTotalLineCount=getDataSize()/g_nBytesProLine;

    if(nTotalLineCount>1) // TODO Check
    {
        nTotalLineCount--;
    }

    setTotalLineCount(nTotalLineCount);

    setCurrentIPAddress(options.nCurrentIPAddress);

    if(options.nInitAddress)
    {
        qint64 nOffset=XBinary::addressToOffset(getMemoryMap(),options.nInitAddress);

        if(nOffset==-1)
        {
            nOffset=0;
        }

        _goToOffset(nOffset);
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

    g_mapOpcodes=XCapstone::getOpcodeColorMap(disasmMode);

    XCapstone::closeHandle(&g_handle);
    XCapstone::openHandle(disasmMode,&g_handle,true);
}

XBinary::DM XDisasmView::getMode()
{
    return g_disasmMode;
}

void XDisasmView::setCurrentIPAddress(qint64 nAddress)
{
    g_nCurrentIP=nAddress;
}

qint64 XDisasmView::getSelectionInitAddress()
{
    qint64 nResult=-1;

    qint64 nOffset=getSelectionInitOffset();

    if(nOffset!=-1)
    {
        nResult=XBinary::offsetToAddress(getMemoryMap(),nOffset);
    }

    return nResult;
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
        nEndOffset=qMin(nEndOffset,getDataSize());

        if(nOffset>nOldOffset)
        {
            nStartOffset=qMax(nStartOffset,nOldOffset);
        }

        qint32 nSize=nEndOffset-nStartOffset;

        QByteArray baData=read_array(nStartOffset,nSize);

        nSize=baData.size();

        qint64 _nCurrentOffset=0;

        // TODO nOffset<nOldOffset
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

XDisasmView::MENU_STATE XDisasmView::getMenuState()
{
    MENU_STATE result={};

    STATE state=getState();

//    if(state.nCursorOffset!=XBinary::offsetToAddress(&(g_options.memoryMap),state.nCursorOffset))
//    {
//        result.bOffset=true;
//    }

    if(state.nSelectionSize)
    {
        result.bSize=true;
    }

    if(g_options.bMenu_Hex)
    {
        result.bHex=true;
    }

    return result;
}

void XDisasmView::drawText(QPainter *pPainter, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight, QString sText, TEXT_OPTION *pTextOption)
{
    QRect rectText;

    rectText.setLeft(nLeft+getCharWidth());
    rectText.setTop(nTop+getLineDelta());
    rectText.setWidth(nWidth);
    rectText.setHeight(nHeight-getLineDelta());

    bool bSave=false;

    if((pTextOption->bCurrentIP))
    {
        bSave=true;
    }

    if(bSave)
    {
        pPainter->save();
    }

    if((pTextOption->bSelected)&&(!pTextOption->bCurrentIP))
    {
        pPainter->fillRect(nLeft,nTop,nWidth,nHeight,viewport()->palette().color(QPalette::Highlight));
    }

    if(pTextOption->bIsReplaced)
    {
        pPainter->fillRect(nLeft,nTop,nWidth,nHeight,QColor(Qt::red));
    }
    else if(pTextOption->bCurrentIP)
    {
        pPainter->fillRect(nLeft,nTop,nWidth,nHeight,viewport()->palette().color(QPalette::WindowText));
        pPainter->setPen(viewport()->palette().color(QPalette::Base));
    }

    if(pTextOption->bHighlight)
    {
        drawDisasmText(pPainter,rectText,sText);
    }
    else
    {
        pPainter->drawText(rectText,sText);
    }

    if(bSave)
    {
        pPainter->restore();
    }
}

void XDisasmView::drawDisasmText(QPainter *pPainter, QRect rect, QString sText)
{
    // TODO registers
    QString sOpcode=sText.section(" ",0,0);

    if(g_mapOpcodes.contains(sOpcode))
    {
        pPainter->save();

        pPainter->setPen(g_mapOpcodes.value(sOpcode));
        pPainter->drawText(rect,sOpcode);

        pPainter->restore();

        QString sOperands=sText.section(" ",1,-1);

        if(sOperands!="")
        {
            QRect _rect=rect;
            _rect.setX(rect.x()+QFontMetrics(pPainter->font()).size(Qt::TextSingleLine,sOpcode+" ").width());
            pPainter->drawText(_rect,sOperands);
        }
    }
    else
    {
        // TODO
        pPainter->drawText(rect,sText);
    }
}

XAbstractTableView::OS XDisasmView::cursorPositionToOS(XAbstractTableView::CURSOR_POSITION cursorPosition)
{
    OS osResult={};
    osResult.nOffset=-1;

    if((cursorPosition.bIsValid)&&(cursorPosition.ptype==PT_CELL))
    {
        if(cursorPosition.nRow<g_listRecords.count())
        {
            qint64 nBlockOffset=g_listRecords.at(cursorPosition.nRow).nOffset;
            qint64 nBlockSize=g_listRecords.at(cursorPosition.nRow).nSize;

            if(cursorPosition.nColumn==COLUMN_ADDRESS)
            {
                osResult.nOffset=nBlockOffset;
                osResult.nSize=nBlockSize;
            }
            else if(cursorPosition.nColumn==COLUMN_OFFSET)
            {
                osResult.nOffset=nBlockOffset;
                osResult.nSize=nBlockSize;
            }
            else if(cursorPosition.nColumn==COLUMN_BYTES)
            {
                // TODO
                osResult.nOffset=nBlockOffset;
                osResult.nSize=nBlockSize;
            }
            else if(cursorPosition.nColumn==COLUMN_OPCODE)
            {
                osResult.nOffset=nBlockOffset;
                osResult.nSize=nBlockSize;
            }
            else if(cursorPosition.nColumn==COLUMN_COMMENT)
            {
                osResult.nOffset=nBlockOffset;
                osResult.nSize=nBlockSize;
            }
        }
        else
        {
            if(!isOffsetValid(osResult.nOffset))
            {
                osResult.nOffset=getDataSize(); // TODO Check
                osResult.nSize=0;
            }
        }
    }

    return osResult;
}

void XDisasmView::updateData()
{
    g_listRecords.clear();

    if(getDevice())
    {
        qint64 nBlockOffset=getViewStart()*g_nBytesProLine; // mb TODO remove BytesProLine!

        qint32 nNumberLinesProPage=getLinesProPage();

        qint64 nCurrentOffset=nBlockOffset;

        for(int i=0;i<nNumberLinesProPage;i++)
        {
            if(nCurrentOffset<getDataSize())
            {
                qint32 nBufferSize=qMin(g_nOpcodeSize,qint32(getDataSize()-nCurrentOffset));

                QByteArray baBuffer=read_array(nCurrentOffset,nBufferSize);

                nBufferSize=baBuffer.size();

                if(nBufferSize==0)
                {
                    break;
                }

                RECORD record={};

                qint64 nCurrentAddress=0;

                if(getAddressMode()==MODE_ADDRESS)
                {
                    nCurrentAddress=XBinary::offsetToAddress(getMemoryMap(),nCurrentOffset);
                }
                else if(getAddressMode()==MODE_RELADDRESS)
                {
                    nCurrentAddress=XBinary::offsetToRelAddress(getMemoryMap(),nCurrentOffset);
                }

                record.nOffset=nCurrentOffset;
                record.sOffset=QString("%1").arg(nCurrentOffset,g_nAddressWidth,16,QChar('0'));

                record.nAddress=nCurrentAddress;

                if(nCurrentAddress!=-1)
                {
                    record.sAddress=QString("%1").arg(nCurrentAddress,g_nAddressWidth,16,QChar('0'));
                }

                DISASM_RESULT disasmResult=_disasm(baBuffer.data(),nBufferSize,nCurrentAddress);

                record.sOpcode=disasmResult.sOpcode;
                record.nSize=disasmResult.nSize;
                nBufferSize=disasmResult.nSize;

                baBuffer.resize(nBufferSize);
                record.sHEX=baBuffer.toHex().data();

                record.bIsReplaced=isReplaced(record.nOffset,record.nSize);

                g_listRecords.append(record);

                nCurrentOffset+=nBufferSize;
            }
        }

        setCurrentBlock(nBlockOffset,(nCurrentOffset-nBlockOffset));
    }
}

void XDisasmView::paintCell(QPainter *pPainter, qint32 nRow, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{
    qint32 nNumberOfRows=g_listRecords.count();

    if(nRow<nNumberOfRows)
    {
        qint64 nOffset=g_listRecords.at(nRow).nOffset;
        qint64 nAddress=g_listRecords.at(nRow).nAddress;

        TEXT_OPTION textOption={};
        textOption.bSelected=isOffsetSelected(nOffset);
        textOption.bCurrentIP=((g_nCurrentIP!=-1)&&(nAddress==g_nCurrentIP)&&(nColumn==COLUMN_ADDRESS));
        textOption.bIsReplaced=((g_listRecords.at(nRow).bIsReplaced)&&(nColumn==COLUMN_ADDRESS)); 

        if(nColumn==COLUMN_ADDRESS)
        {
            drawText(pPainter,nLeft,nTop,nWidth,nHeight,g_listRecords.at(nRow).sAddress,&textOption);
        }
        else if(nColumn==COLUMN_OFFSET)
        {
            drawText(pPainter,nLeft,nTop,nWidth,nHeight,g_listRecords.at(nRow).sOffset,&textOption);
        }
        else if(nColumn==COLUMN_BYTES)
        {
            drawText(pPainter,nLeft,nTop,nWidth,nHeight,g_listRecords.at(nRow).sHEX,&textOption);
        }
        else if(nColumn==COLUMN_OPCODE)
        {
            textOption.bHighlight=true;
            drawText(pPainter,nLeft,nTop,nWidth,nHeight,g_listRecords.at(nRow).sOpcode,&textOption);
        }
        else if(nColumn==COLUMN_COMMENT)
        {
            drawText(pPainter,nLeft,nTop,nWidth,nHeight,g_listRecords.at(nRow).sCommemt,&textOption);
        }
    }
}

void XDisasmView::contextMenu(const QPoint &pos)
{
    QAction actionGoToAddress(tr("Go to address"),this);
    actionGoToAddress.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_GOTOADDRESS));
    connect(&actionGoToAddress,SIGNAL(triggered()),this,SLOT(_goToAddressSlot()));

    QAction actionGoToOffset(tr("Go to offset"),this);
    actionGoToOffset.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_GOTOOFFSET));
    connect(&actionGoToOffset,SIGNAL(triggered()),this,SLOT(_goToOffsetSlot()));

    QAction actionGoToEntryPoint(tr("Go to entry point"),this);
    actionGoToEntryPoint.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_GOTOENTRYPOINT));
    connect(&actionGoToEntryPoint,SIGNAL(triggered()),this,SLOT(_goToEntryPointSlot()));

    QAction actionDumpToFile(tr("Dump to file"),this);
    actionDumpToFile.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_DUMPTOFILE));
    connect(&actionDumpToFile,SIGNAL(triggered()),this,SLOT(_dumpToFileSlot()));

    QAction actionHexSignature(tr("Hex signature"),this);
    actionHexSignature.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_HEXSIGNATURE));
    connect(&actionHexSignature,SIGNAL(triggered()),this,SLOT(_hexSignatureSlot()));

    QAction actionSignature(tr("Signature"),this);
    actionSignature.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_SIGNATURE));
    connect(&actionSignature,SIGNAL(triggered()),this,SLOT(_signatureSlot()));

    QAction actionFind(tr("Find"),this);
    actionFind.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_FIND));
    connect(&actionFind,SIGNAL(triggered()),this,SLOT(_findSlot()));

    QAction actionFindNext(tr("Find next"),this);
    actionFindNext.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_FINDNEXT));
    connect(&actionFindNext,SIGNAL(triggered()),this,SLOT(_findNextSlot()));

    QAction actionSelectAll(tr("Select all"),this);
    actionSelectAll.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_SELECTALL));
    connect(&actionSelectAll,SIGNAL(triggered()),this,SLOT(_selectAllSlot()));

    QAction actionCopyAsHex(tr("Copy as hex"),this);
    actionCopyAsHex.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_COPYASHEX));
    connect(&actionCopyAsHex,SIGNAL(triggered()),this,SLOT(_copyAsHexSlot()));

    QAction actionCopyCursorOffset(tr("Copy cursor offset"),this);
    actionCopyCursorOffset.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_COPYCURSOROFFSET));
    connect(&actionCopyCursorOffset,SIGNAL(triggered()),this,SLOT(_copyCursorOffsetSlot()));

    QAction actionCopyCursorAddress(tr("Copy cursor address"),this);
    actionCopyCursorAddress.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_COPYCURSORADDRESS));
    connect(&actionCopyCursorAddress,SIGNAL(triggered()),this,SLOT(_copyCursorAddressSlot()));

    QAction actionHex(tr("Hex"),this);
    actionHex.setShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_HEX));
    connect(&actionHex,SIGNAL(triggered()),this,SLOT(_hexSlot()));

    MENU_STATE menuState=getMenuState();

    QMenu contextMenu(this);
    QMenu menuGoTo(tr("Go to"),this);
    QMenu menuSelect(tr("Select"),this);
    QMenu menuCopy(tr("Copy"),this);

    menuSelect.addAction(&actionSelectAll);

    menuGoTo.addAction(&actionGoToAddress);
    menuGoTo.addAction(&actionGoToOffset);
    menuGoTo.addAction(&actionGoToEntryPoint);

    menuCopy.addAction(&actionCopyCursorAddress);
    menuCopy.addAction(&actionCopyCursorOffset);

    if(menuState.bSize)
    {
        menuCopy.addAction(&actionCopyAsHex);
    }

    contextMenu.addAction(&actionFind);
    contextMenu.addAction(&actionFindNext);

    if(menuState.bSize)
    {
        contextMenu.addAction(&actionDumpToFile);
        contextMenu.addAction(&actionSignature);
        contextMenu.addAction(&actionHexSignature);
    }

    if(menuState.bHex)
    {
        contextMenu.addAction(&actionHex);
    }

    contextMenu.addMenu(&menuGoTo);
    contextMenu.addMenu(&menuCopy);
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

    if(getDataSize()>nMaxValue)
    {
        if(nValue==getMaxScrollValue())
        {
            nResult=getDataSize()-g_nBytesProLine;
        }
        else
        {
            nResult=((double)nValue/(double)getMaxScrollValue())*getDataSize();
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

    if(getDataSize()>(getMaxScrollValue()*g_nBytesProLine))
    {
        if(nOffset==getDataSize()-g_nBytesProLine)
        {
            nValue=getMaxScrollValue();
        }
        else
        {
            nValue=((double)(nOffset)/((double)getDataSize()))*(double)getMaxScrollValue();
        }
    }
    else
    {
        nValue=(nOffset)/g_nBytesProLine;
    }

    verticalScrollBar()->setValue(nValue);

    adjust(true);
}

void XDisasmView::adjustColumns()
{
    setColumnEnabled(COLUMN_OFFSET,!(g_options.bHideOffset));

    const QFontMetricsF fm(getTextFont());

    if(XBinary::getWidthModeFromSize(getDataSize())==XBinary::MODE_64)
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

    QString sBytes;

    for(int i=0;i<g_nOpcodeSize;i++)
    {
        sBytes+="00";
    }

    setColumnWidth(COLUMN_BYTES,2*getCharWidth()+fm.boundingRect(sBytes).width());
    setColumnWidth(COLUMN_OPCODE,40*getCharWidth());
    setColumnWidth(COLUMN_COMMENT,40*getCharWidth());
}

void XDisasmView::registerShortcuts(bool bState)
{
    if(bState)
    {
        if(!g_scGoToAddress)        g_scGoToAddress         =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_GOTOADDRESS),          this,SLOT(_goToAddressSlot()));
        if(!g_scGoToOffset)         g_scGoToOffset          =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_GOTOOFFSET),           this,SLOT(_goToOffsetSlot()));
        if(!g_scGoToEntryPoint)     g_scGoToEntryPoint      =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_GOTOENTRYPOINT),       this,SLOT(_goToEntryPointSlot()));
        if(!g_scDumpToFile)         g_scDumpToFile          =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_DUMPTOFILE),           this,SLOT(_dumpToFileSlot()));
        if(!g_scSelectAll)          g_scSelectAll           =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_SELECTALL),            this,SLOT(_selectAllSlot()));
        if(!g_scCopyAsHex)          g_scCopyAsHex           =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_COPYASHEX),            this,SLOT(_copyAsHexSlot()));
        if(!g_scCopyCursorAddress)  g_scCopyCursorAddress   =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_COPYCURSORADDRESS),    this,SLOT(_copyCursorAddressSlot()));
        if(!g_scCopyCursorOffset)   g_scCopyCursorOffset    =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_COPYCURSOROFFSET),     this,SLOT(_copyCursorOffsetSlot()));
        if(!g_scFind)               g_scFind                =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_FIND),                 this,SLOT(_findSlot()));
        if(!g_scFindNext)           g_scFindNext            =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_FINDNEXT),             this,SLOT(_findNextSlot()));
        if(!g_scSignature)          g_scSignature           =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_SIGNATURE),            this,SLOT(_signatureSlot()));
        if(!g_scHexSignature)       g_scHexSignature        =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_HEXSIGNATURE),         this,SLOT(_hexSignatureSlot()));
        if(!g_scHex)                g_scHex                 =new QShortcut(getShortcuts()->getShortcut(XShortcuts::ID_DISASM_HEX),                  this,SLOT(_hexSlot()));
    }
    else
    {
        if(g_scGoToAddress)         {delete g_scGoToAddress;        g_scGoToAddress=nullptr;}
        if(g_scGoToOffset)          {delete g_scGoToOffset;         g_scGoToOffset=nullptr;}
        if(g_scGoToEntryPoint)      {delete g_scGoToEntryPoint;     g_scGoToEntryPoint=nullptr;}
        if(g_scDumpToFile)          {delete g_scDumpToFile;         g_scDumpToFile=nullptr;}
        if(g_scSelectAll)           {delete g_scSelectAll;          g_scSelectAll=nullptr;}
        if(g_scCopyAsHex)           {delete g_scCopyAsHex;          g_scCopyAsHex=nullptr;}
        if(g_scCopyCursorAddress)   {delete g_scCopyCursorAddress;  g_scCopyCursorAddress=nullptr;}
        if(g_scCopyCursorOffset)    {delete g_scCopyCursorOffset;   g_scCopyCursorOffset=nullptr;}
        if(g_scFind)                {delete g_scFind;               g_scFind=nullptr;}
        if(g_scFindNext)            {delete g_scFindNext;           g_scFindNext=nullptr;}
        if(g_scSignature)           {delete g_scSignature;          g_scSignature=nullptr;}
        if(g_scHexSignature)        {delete g_scHexSignature;       g_scHexSignature=nullptr;}
        if(g_scHex)                 {delete g_scHex;                g_scHex=nullptr;}
    }
}

void XDisasmView::_headerClicked(qint32 nNumber)
{
    if(nNumber==COLUMN_ADDRESS)
    {
        if(getAddressMode()==MODE_ADDRESS)
        {
            setColumnTitle(COLUMN_ADDRESS,tr("Address"));
            setAddressMode(MODE_RELADDRESS);
        }
        else if(getAddressMode()==MODE_RELADDRESS)
        {
            setColumnTitle(COLUMN_ADDRESS,tr("Relative address"));
            setAddressMode(MODE_ADDRESS);
        }

        adjust(true);
    }
}

void XDisasmView::_goToEntryPointSlot()
{
    goToAddress(g_options.nEntryPointAddress);
    setFocus();
    viewport()->update();
}

void XDisasmView::_signatureSlot()
{
    STATE state=getState();

    DialogMultiDisasmSignature dmds(this);

    dmds.setData(getDevice(),state.nSelectionOffset,getMemoryMap(),g_handle,g_options.sSignaturesPath);

    dmds.setShortcuts(getShortcuts());

    dmds.exec();
}

void XDisasmView::_hexSlot()
{
    if(g_options.bMenu_Hex)
    {
        // TODO
    }
}
