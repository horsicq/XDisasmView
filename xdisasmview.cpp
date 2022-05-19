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
#include "xdisasmview.h"
#include "xdisasmview.h"

XDisasmView::XDisasmView(QWidget *pParent) : XDeviceTableView(pParent)
{
    // TODO click on Address -> Offset
    g_handle=0;

    g_nBytesProLine=1;

    memset(shortCuts,0,sizeof shortCuts);

    g_options=OPTIONS();

    g_nCurrentIP=-1;
    g_nAddressWidth=8;
    g_nOpcodeSize=16;

    g_nThisBase=0;
    g_bIsAddressColon=false;
    g_bIsHighlight=false;
    g_syntax=XBinary::SYNTAX_DEFAULT;
    g_modeOpcode=MODE_OPCODE_SYMBOLADDRESS;

    addColumn(""); // Arrows
//    addColumn(tr("Address"),0,true);
    addColumn(tr("Address"),0,true);
//    addColumn(tr("Offset"));
    addColumn(tr("Bytes"));
    addColumn(QString("%1(%2->%3)").arg(tr("Opcode"),tr("Symbol"),tr("Address")),0,true); // TODO fix it in _adjustWindow
    addColumn(tr("Comment"));

//    setLastColumnStretch(true);

    setTextFont(getMonoFont());

    setAddressMode(MODE_ADDRESS);
}

XDisasmView::~XDisasmView()
{
    if(g_handle)
    {
        XCapstone::closeHandle(&g_handle);
    }
}

void XDisasmView::_adjustView()
{
    QFont _font;
    QString sFont=getGlobalOptions()->getValue(XOptions::ID_DISASM_FONT).toString();

    if((sFont!="")&&_font.fromString(sFont))
    {
        setTextFont(_font);
    }
    // mb TODO errorString

    g_bIsHighlight=getGlobalOptions()->getValue(XOptions::ID_DISASM_HIGHLIGHT).toBool();
    g_bIsAddressColon=getGlobalOptions()->getValue(XOptions::ID_DISASM_ADDRESSCOLON).toBool();

    g_syntax=XBinary::stringToSyntaxId(getGlobalOptions()->getValue(XOptions::ID_DISASM_SYNTAX).toString());

    g_mapOpcodes=getOpcodeColorMap(g_disasmMode,g_syntax);

    if(g_handle)
    {
        XCapstone::closeHandle(&g_handle);
    }

    XCapstone::openHandle(g_disasmMode,&g_handle,true,g_syntax);
}

void XDisasmView::adjustView()
{
    _adjustView();

    reload(true);
}

void XDisasmView::setData(QIODevice *pDevice,XDisasmView::OPTIONS options,bool bReload)
{
    g_options=options;

    setDevice(pDevice);
    setMemoryMap(g_options.memoryMap);

    XBinary::DM disasmMode=XBinary::getDisasmMode(getMemoryMap());

    setMode(disasmMode);

    adjustColumns();

    qint64 nTotalLineCount=getDataSize()/g_nBytesProLine;

    if(nTotalLineCount>1) // TODO Check
    {
        nTotalLineCount--;
    }

    setTotalLineCount(nTotalLineCount);

    setCurrentPointerAddress(options.nCurrentIPAddress);

    if(options.nInitAddress!=-1)
    {
        qint64 nOffset=XBinary::addressToOffset(getMemoryMap(),options.nInitAddress);

        if(nOffset==-1)
        {
            nOffset=0;
        }

        _goToOffset(nOffset);
    }
//    else
//    {
//        setScrollValue(0);
//    }

    if(bReload)
    {
        reload(true);
    }
}

void XDisasmView::setMode(XBinary::DM disasmMode)
{
    g_disasmMode=disasmMode;

    _adjustView();
}

XBinary::DM XDisasmView::getMode()
{
    return g_disasmMode;
}

void XDisasmView::setCurrentPointerAddress(XADDR nAddress)
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

XDisasmView::DISASM_RESULT XDisasmView::_disasm(char *pData,qint32 nDataSize,quint64 nAddress,MODE mode)
{
    DISASM_RESULT result={};

    result.mode=mode;
    result.nAddress=nAddress;

    if(g_handle)
    {
        cs_insn *pInsn=nullptr;

        quint64 nNumberOfOpcodes=cs_disasm(g_handle,(uint8_t *)pData,nDataSize,nAddress,1,&pInsn);

        if(nNumberOfOpcodes>0)
        {
            result.sMnemonic=pInsn->mnemonic;
            result.sString=pInsn->op_str;

//            result.sOpcode+=sMnemonic;
//            if(sStr!="")
//            {
//                result.sOpcode+=QString("|%1").arg(sStr);
//            }

            result.nSize=pInsn->size;
            result.bIsValid=true;

            qint32 nNumberOfGroups=pInsn->detail->groups_count;

            for(qint32 i=0;i<nNumberOfGroups;i++)
            {
                if(pInsn->detail->groups[i]==CS_GRP_BRANCH_RELATIVE)
                {
                    if(XBinary::getDisasmFamily(g_disasmMode)==XBinary::DMFAMILY_X86)
                    {
                        for(qint32 j=0;j<pInsn->detail->x86.op_count;j++)
                        {
                            if(pInsn->detail->x86.operands[j].type==X86_OP_IMM)
                            {
                                result.bRelative=true;
                                result.nXrefTo=pInsn->detail->x86.operands[j].imm;

                                break;
                            }
                        }
                    }
                    else if(XBinary::getDisasmFamily(g_disasmMode)==XBinary::DMFAMILY_ARM)
                    {
                        for(qint32 j=0;j<pInsn->detail->arm.op_count;j++)
                        {
                            if(pInsn->detail->arm.operands[j].type==ARM_OP_IMM)
                            {
                                result.bRelative=true;
                                result.nXrefTo=pInsn->detail->arm.operands[j].imm;

                                break;
                            }
                        }
                    }
                    else if(XBinary::getDisasmFamily(g_disasmMode)==XBinary::DMFAMILY_ARM64)
                    {
                        for(qint32 j=0;j<pInsn->detail->arm64.op_count;j++)
                        {
                            if(pInsn->detail->arm64.operands[j].type==ARM_OP_IMM)
                            {
                                result.bRelative=true;
                                result.nXrefTo=pInsn->detail->arm64.operands[j].imm;

                                break;
                            }
                        }
                    }

                    break;
                }
            }

            if(result.bRelative)
            {
                if( (g_modeOpcode==MODE_OPCODE_SYMBOLADDRESS)||
                    (g_modeOpcode==MODE_OPCODE_SYMBOL)||
                    (g_modeOpcode==MODE_OPCODE_ADDRESS))
                {
                    XInfoDB::RI_TYPE riType=XInfoDB::RI_TYPE_SYMBOLADDRESS;

                    if(g_modeOpcode==MODE_OPCODE_SYMBOLADDRESS)
                    {
                        riType=XInfoDB::RI_TYPE_SYMBOLADDRESS;
                    }
                    else if(g_modeOpcode==MODE_OPCODE_SYMBOL)
                    {
                        riType=XInfoDB::RI_TYPE_SYMBOL;
                    }
                    else if(g_modeOpcode==MODE_OPCODE_ADDRESS)
                    {
                        riType=XInfoDB::RI_TYPE_ADDRESS;
                    }

                    if(getXInfoDB())
                    {
                        QString sReplace=XInfoDB::recordInfoToString(getXInfoDB()->getRecordInfoCache(result.nXrefTo),riType);

                        if(sReplace!="")
                        {
                            QString sOrigin=QString("0x%1").arg(QString::number(result.nXrefTo,16));
                            result.sString=result.sString.replace(sOrigin,sReplace);
                        }
                    }
                }
            }

            cs_free(pInsn,nNumberOfOpcodes);
        }
        else
        {
            result.sMnemonic=tr("Invalid opcode");
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

        if(XBinary::getDisasmFamily(g_disasmMode)==XBinary::DMFAMILY_ARM) // TODO Check
        {
            nStartOffset=S_ALIGN_DOWN(nStartOffset,4);
        }
        else if(XBinary::getDisasmFamily(g_disasmMode)==XBinary::DMFAMILY_ARM64)
        {
            nStartOffset=S_ALIGN_DOWN(nStartOffset,4);
        }

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

            DISASM_RESULT disasmResult=_disasm(baData.data()+_nCurrentOffset,nSize,_nCurrentOffset,MODE_ADDRESS);

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

void XDisasmView::drawText(QPainter *pPainter,qint32 nLeft,qint32 nTop,qint32 nWidth,qint32 nHeight,QString sText,TEXT_OPTION *pTextOption)
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

void XDisasmView::drawDisasmText(QPainter *pPainter,QRect rect,QString sText)
{
    QString sMnemonic=sText.section("|",0,0);
    QString sString=sText.section("|",1,1);
    // TODO registers !!!
    // TODO upper case
    if(g_bIsHighlight&&g_mapOpcodes.contains(sMnemonic))
    {
        OPCODECOLOR opcodeColor=g_mapOpcodes.value(sMnemonic);

        pPainter->save();

        QRect _rect=rect;

        _rect.setWidth(QFontMetrics(pPainter->font()).size(Qt::TextSingleLine,sMnemonic).width());

        if(opcodeColor.colBackground.isValid())
        {
            pPainter->fillRect(_rect,QBrush(opcodeColor.colBackground));
        }

        pPainter->setPen(opcodeColor.colText);
        pPainter->drawText(_rect,sMnemonic);

        pPainter->restore();

        if(sString!="")
        {
            QRect _rect=rect;
            _rect.setX(rect.x()+QFontMetrics(pPainter->font()).size(Qt::TextSingleLine,sMnemonic+" ").width());

            pPainter->drawText(_rect,sString);
        }
    }
    else
    {
        QString sOpcode=sMnemonic;

        if(sString!="")
        {
            sOpcode+=QString(" %1").arg(sString);
        }
        // TODO
        pPainter->drawText(rect,sOpcode);
    }
}

void XDisasmView::drawArrow(QPainter *pPainter,QPointF pointStart,QPointF pointEnd)
{
    QPolygonF arrowHead;
    qreal arrowSize=8;

    QLineF line(pointEnd,pointStart);

    double angle=std::atan2(-line.dy(),line.dx());

    QPointF arrowP1=line.p1()+QPointF(sin(angle+M_PI/3)*arrowSize,cos(angle+M_PI/3)*arrowSize);
    QPointF arrowP2=line.p1()+QPointF(sin(angle+M_PI-M_PI/3)*arrowSize,cos(angle+M_PI-M_PI/3)*arrowSize);

    arrowHead.clear();
    arrowHead << line.p1() << arrowP1 << arrowP2;

    pPainter->drawLine(pointStart,pointEnd);
    pPainter->drawPolygon(arrowHead);
}

QMap<QString,XDisasmView::OPCODECOLOR> XDisasmView::getOpcodeColorMap(XBinary::DM disasmMode,XBinary::SYNTAX syntax)
{
    QMap<QString,OPCODECOLOR> mapResult;

    if(XBinary::getDisasmFamily(disasmMode)==XBinary::DMFAMILY_X86)
    {
        OPCODECOLOR colorCALL=getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_CALL);
        OPCODECOLOR colorJCC=getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_JCC);
        OPCODECOLOR colorRET=getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_RET);
        OPCODECOLOR colorPUSH=getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_PUSH);
        OPCODECOLOR colorPOP=getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_POP);
        OPCODECOLOR colorNOP=getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_NOP);
        OPCODECOLOR colorJMP=getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_JMP);

        if((syntax==XBinary::SYNTAX_DEFAULT)||(syntax==XBinary::SYNTAX_INTEL)||(syntax==XBinary::SYNTAX_MASM))
        {
            mapResult.insert("call",colorCALL);
            mapResult.insert("ret",colorRET);
            mapResult.insert("push",colorPUSH);
            mapResult.insert("pop",colorPOP);
            mapResult.insert("nop",colorNOP);
            mapResult.insert("jmp",colorJMP);
            mapResult.insert("je",colorJCC);
            mapResult.insert("jne",colorJCC);
            mapResult.insert("jz",colorJCC);
            mapResult.insert("jnz",colorJCC);
            mapResult.insert("ja",colorJCC);
        }
        else if(syntax==XBinary::SYNTAX_ATT)
        {
            {
                mapResult.insert("callw",colorCALL);
                mapResult.insert("calll",colorCALL);
                mapResult.insert("callq",colorCALL);
            }
            {
                mapResult.insert("retw",colorRET);
                mapResult.insert("retl",colorRET);
                mapResult.insert("retq",colorRET);
            }
            {
                mapResult.insert("pushw",colorPUSH);
                mapResult.insert("pushl",colorPUSH);
                mapResult.insert("pushq",colorPUSH);
            }
            {
                mapResult.insert("popw",colorPUSH);
                mapResult.insert("popl",colorPUSH);
                mapResult.insert("popq",colorPUSH);
            }

            mapResult.insert("nop",colorNOP);
            mapResult.insert("jmp",colorJMP);
            mapResult.insert("je",colorJCC);
            mapResult.insert("jne",colorJCC);
            mapResult.insert("jz",colorJCC);
            mapResult.insert("jnz",colorJCC);
            mapResult.insert("ja",colorJCC);
        }
    }
    else if((XBinary::getDisasmFamily(disasmMode)==XBinary::DMFAMILY_ARM)||(XBinary::getDisasmFamily(disasmMode)==XBinary::DMFAMILY_ARM64))
    {
        OPCODECOLOR colorBL=getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_BL);
        OPCODECOLOR colorRET=getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_RET);
        OPCODECOLOR colorPUSH=getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_PUSH);
        OPCODECOLOR colorPOP=getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_POP);

        mapResult.insert("bl",colorBL);
        mapResult.insert("ret",colorRET);
        mapResult.insert("push",colorPUSH);
        mapResult.insert("pop",colorPOP);
    }

    return mapResult;
}

XDisasmView::OPCODECOLOR XDisasmView::getOpcodeColor(XOptions::ID id)
{
    OPCODECOLOR result={};

    QString sCode=getGlobalOptions()->getValue(id).toString();
    QString sTextCode=sCode.section("|",0,0);
    QString sBackgroundCode=sCode.section("|",1,1);

    if(sTextCode!="")
    {
        result.colText.setNamedColor(sTextCode);
    }

    if(sBackgroundCode!="")
    {
        result.colBackground.setNamedColor(sBackgroundCode);
    }

    return result;
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
            qint64 nBlockSize=g_listRecords.at(cursorPosition.nRow).disasmResult.nSize;

            if(cursorPosition.nColumn==COLUMN_ADDRESS)
            {
                osResult.nOffset=nBlockOffset;
                osResult.nSize=nBlockSize;
            }
//            else if(cursorPosition.nColumn==COLUMN_OFFSET)
//            {
//                osResult.nOffset=nBlockOffset;
//                osResult.nSize=nBlockSize;
//            }
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
//    g_listArrows.clear();

    if(getDevice())
    {
        if(getXInfoDB())
        {
            QList<XBinary::MEMORY_REPLACE> listMR=getXInfoDB()->getMemoryReplaces(getMemoryMap()->nModuleAddress,getMemoryMap()->nImageSize);

            setMemoryReplaces(listMR);
        }

        XBinary::MODE mode=XBinary::getWidthModeFromByteSize(g_nAddressWidth);

        qint64 nBlockOffset=getViewStart()*g_nBytesProLine; // mb TODO remove BytesProLine!

        qint32 nNumberLinesProPage=getLinesProPage();

        qint64 nCurrentOffset=nBlockOffset;

        for(qint32 i=0;i<nNumberLinesProPage;i++)
        {
            if(nCurrentOffset<getDataSize())
            {
                qint32 nBufferSize=qMin(g_nOpcodeSize,qint32(getDataSize()-nCurrentOffset));

//                qDebug("DELTA: %d BS: %d",qint32(getDataSize()-nCurrentOffset),nBufferSize);

                QByteArray baBuffer=read_array(nCurrentOffset,nBufferSize);

                nBufferSize=baBuffer.size();

//                qDebug("BS: %d",nBufferSize);

                if(nBufferSize==0)
                {
                    break;
                }

                RECORD record={};
                record.nOffset=nCurrentOffset;
                record.nAddress=XBinary::offsetToAddress(getMemoryMap(),nCurrentOffset);

                XADDR _nCurrent=0;

                if(getAddressMode()==MODE_THIS)
                {
                    _nCurrent=record.nAddress;

                    qint64 nDelta=(qint64)_nCurrent-(qint64)g_nThisBase;

                    record.sAddress=XBinary::thisToString(nDelta);
                }
                else
                {
                    if(getAddressMode()==MODE_ADDRESS)
                    {
                        _nCurrent=record.nAddress;
                    }
                    else if(getAddressMode()==MODE_OFFSET)
                    {
                        _nCurrent=record.nOffset;
                    }
                    else if(getAddressMode()==MODE_RELADDRESS)
                    {
                        _nCurrent=XBinary::offsetToRelAddress(getMemoryMap(),nCurrentOffset);
                    }

    //                record.sOffset=XBinary::valueToHexColon(mode,nCurrentOffset);

                    if(_nCurrent==(XADDR)-1)
                    {
                        _nCurrent=nCurrentOffset;
                    }

                    if(g_bIsAddressColon)
                    {
                        record.sAddress=XBinary::valueToHexColon(mode,_nCurrent);
                    }
                    else
                    {
                        record.sAddress=XBinary::valueToHex(mode,_nCurrent);
                    }
                }

                record.disasmResult=_disasm(baBuffer.data(),nBufferSize,record.nAddress,getAddressMode());

                nBufferSize=record.disasmResult.nSize;

                baBuffer.resize(nBufferSize);
                record.sHEX=baBuffer.toHex().data();

                record.bIsReplaced=isReplaced(record.nOffset,nBufferSize);

                g_listRecords.append(record);

                nCurrentOffset+=nBufferSize;
            }
            else
            {
                break;
            }
        }

        qint32 nNumberOfRecords=g_listRecords.count();

        if(nNumberOfRecords)
        {
            for(qint32 i=0;i<nNumberOfRecords;i++)
            {
                if(g_listRecords.at(i).disasmResult.bRelative)
                {
                    XADDR nXrefTo=g_listRecords.at(i).disasmResult.nXrefTo;
                    XADDR nCurrentAddress=g_listRecords.at(i).nAddress;

                    qint32 nStart=0;
                    qint32 nEnd=nNumberOfRecords-1;
                    qint32 nMaxLevel=0;

                    if(nCurrentAddress>nXrefTo)
                    {
                        nEnd=i;

                        g_listRecords[i].nArraySize=nEnd;

                        for(qint32 j=i;j>=nStart;j--)
                        {
                            nMaxLevel=qMax(g_listRecords.at(j).nMaxLevel,nMaxLevel);

                            if((nXrefTo>=g_listRecords.at(j).nAddress)&&(nXrefTo<(g_listRecords.at(j).nAddress+g_listRecords.at(j).disasmResult.nSize)))
                            {
                                nStart=j;
                                g_listRecords[i].nArraySize=nEnd-nStart;
                                g_listRecords[i].bIsEnd=true;

                                break;
                            }
                        }

                        g_listRecords[i].array=ARRAY_UP;
                    }
                    else if(nCurrentAddress<nXrefTo)
                    {
                        nStart=i;

                        g_listRecords[i].nArraySize=nNumberOfRecords-nStart;

                        for(qint32 j=i;j<=nEnd;j++)
                        {
                            nMaxLevel=qMax(g_listRecords.at(j).nMaxLevel,nMaxLevel);

                            if((nXrefTo>=g_listRecords.at(j).nAddress)&&(nXrefTo<(g_listRecords.at(j).nAddress+g_listRecords.at(j).disasmResult.nSize)))
                            {
                                nEnd=j;
                                g_listRecords[i].nArraySize=nEnd-nStart;
                                g_listRecords[i].bIsEnd=true;

                                break;
                            }
                        }

                        g_listRecords[i].array=ARRAY_DOWN;
                    }

                    g_listRecords[i].nArrayLevel=nMaxLevel+1;

                    for(qint32 j=nStart;j<=nEnd;j++)
                    {
                        g_listRecords[j].nMaxLevel=nMaxLevel+1;
                    }
                }
            }
        }

        setCurrentBlock(nBlockOffset,(nCurrentOffset-nBlockOffset));
    }
}

void XDisasmView::paintColumn(QPainter *pPainter,qint32 nColumn,qint32 nLeft,qint32 nTop,qint32 nWidth,qint32 nHeight)
{
    Q_UNUSED(nHeight)

    if(nColumn==COLUMN_ARROWS)
    {
        qint32 nNumberOfRecords=g_listRecords.count();

        if(nNumberOfRecords)
        {
            for(qint32 i=0;i<nNumberOfRecords;i++)
            {
                // TODO DashLine
                if(g_listRecords.at(i).disasmResult.bRelative)
                {
                    QPointF point1;
                    point1.setX(nLeft+nWidth);
                    point1.setY(nTop+((i+0.5)*getLineHeight()));

                    QPointF point2;
                    point2.setX((nLeft+nWidth)-getCharWidth()*(g_listRecords.at(i).nArrayLevel));
                    point2.setY(point1.y());

                    QPointF point3;

                    point3.setX(point2.x());

                    qint32 nDelta=getLineHeight()*g_listRecords.at(i).nArraySize;

                    if(!(g_listRecords.at(i).bIsEnd))
                    {
                        nDelta+=0.5*getLineHeight();
                    }

                    if(g_listRecords.at(i).array==ARRAY_UP)
                    {
                        point3.setY(point1.y()-nDelta);
                    }
                    else if(g_listRecords.at(i).array==ARRAY_DOWN)
                    {
                        point3.setY(point1.y()+nDelta);
                    }

                    pPainter->drawLine(point1,point2);

                    if(g_listRecords.at(i).bIsEnd)
                    {
                        pPainter->drawLine(point2,point3);

                        QPointF point4;
                        point4.setX(point1.x());
                        point4.setY(point3.y());

                        drawArrow(pPainter,point3,point4);
                    }
                    else
                    {
                        drawArrow(pPainter,point2,point3);
                    }
                }
            }
        }
    }
}

void XDisasmView::paintCell(QPainter *pPainter,qint32 nRow,qint32 nColumn,qint32 nLeft,qint32 nTop,qint32 nWidth,qint32 nHeight)
{
    qint32 nNumberOfRows=g_listRecords.count();

    if(nRow<nNumberOfRows)
    {
        qint64 nOffset=g_listRecords.at(nRow).nOffset;
        XADDR nAddress=g_listRecords.at(nRow).disasmResult.nAddress;

        TEXT_OPTION textOption={};
        textOption.bSelected=isOffsetSelected(nOffset);
        textOption.bCurrentIP=((g_nCurrentIP!=-1)&&(nAddress==g_nCurrentIP)&&(nColumn==COLUMN_ADDRESS));
        textOption.bIsReplaced=((g_listRecords.at(nRow).bIsReplaced)&&(nColumn==COLUMN_ADDRESS)); 

        if(nColumn==COLUMN_ARROWS)
        {
            // TODO
        }
        else if(nColumn==COLUMN_ADDRESS)
        {
            drawText(pPainter,nLeft,nTop,nWidth,nHeight,g_listRecords.at(nRow).sAddress,&textOption);
        }
//        else if(nColumn==COLUMN_OFFSET)
//        {
//            drawText(pPainter,nLeft,nTop,nWidth,nHeight,g_listRecords.at(nRow).sOffset,&textOption);
//        }
        else if(nColumn==COLUMN_BYTES)
        {
            drawText(pPainter,nLeft,nTop,nWidth,nHeight,g_listRecords.at(nRow).sHEX,&textOption);
        }
        else if(nColumn==COLUMN_OPCODE)
        {
            QString sOpcode=QString("%1|%2").arg(g_listRecords.at(nRow).disasmResult.sMnemonic,g_listRecords.at(nRow).disasmResult.sString);

            textOption.bHighlight=true;
            drawText(pPainter,nLeft,nTop,nWidth,nHeight,sOpcode,&textOption);
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
    actionGoToAddress.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ADDRESS));
    connect(&actionGoToAddress,SIGNAL(triggered()),this,SLOT(_goToAddressSlot()));

    QAction actionGoToOffset(tr("Go to offset"),this);
    actionGoToOffset.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_OFFSET));
    connect(&actionGoToOffset,SIGNAL(triggered()),this,SLOT(_goToOffsetSlot()));

    QAction actionGoToEntryPoint(tr("Go to entry point"),this);
    actionGoToEntryPoint.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ENTRYPOINT));
    connect(&actionGoToEntryPoint,SIGNAL(triggered()),this,SLOT(_goToEntryPointSlot()));

    QAction actionDumpToFile(tr("Dump to file"),this);
    actionDumpToFile.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_DUMPTOFILE));
    connect(&actionDumpToFile,SIGNAL(triggered()),this,SLOT(_dumpToFileSlot()));

    QAction actionHexSignature(tr("Hex signature"),this);
    actionHexSignature.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_HEX_SIGNATURE));
    connect(&actionHexSignature,SIGNAL(triggered()),this,SLOT(_hexSignatureSlot()));

    QAction actionSignature(tr("Signature"),this);
    actionSignature.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SIGNATURE));
    connect(&actionSignature,SIGNAL(triggered()),this,SLOT(_signatureSlot()));

    QAction actionFindString(tr("String"),this);
    actionFindString.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_STRING));
    connect(&actionFindString,SIGNAL(triggered()),this,SLOT(_findStringSlot()));

    QAction actionFindSignature(tr("Signature"),this);
    actionFindSignature.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_SIGNATURE));
    connect(&actionFindSignature,SIGNAL(triggered()),this,SLOT(_findSignatureSlot()));

    QAction actionFindValue(tr("Value"),this);
    actionFindValue.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_VALUE));
    connect(&actionFindValue,SIGNAL(triggered()),this,SLOT(_findValueSlot()));

    QAction actionFindNext(tr("Find next"),this);
    actionFindNext.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_NEXT));
    connect(&actionFindNext,SIGNAL(triggered()),this,SLOT(_findNextSlot()));

    QAction actionSelectAll(tr("Select all"),this);
    actionSelectAll.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SELECT_ALL));
    connect(&actionSelectAll,SIGNAL(triggered()),this,SLOT(_selectAllSlot()));

    QAction actionCopyAsHex(tr("Copy as hex"),this);
    actionCopyAsHex.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_HEX));
    connect(&actionCopyAsHex,SIGNAL(triggered()),this,SLOT(_copyHexSlot()));

    QAction actionCopyCursorOffset(tr("Copy cursor offset"),this);
    actionCopyCursorOffset.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_OFFSET));
    connect(&actionCopyCursorOffset,SIGNAL(triggered()),this,SLOT(_copyOffsetSlot()));

    QAction actionCopyCursorAddress(tr("Copy cursor address"),this);
    actionCopyCursorAddress.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_ADDRESS));
    connect(&actionCopyCursorAddress,SIGNAL(triggered()),this,SLOT(_copyAddressSlot()));

    QAction actionHex(tr("Hex"),this);
    actionHex.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FOLLOWIN_HEX));
    connect(&actionHex,SIGNAL(triggered()),this,SLOT(_hexSlot()));

    QAction actionEditHex(tr("Hex"),this);
    actionEditHex.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_EDIT_HEX));
    connect(&actionEditHex,SIGNAL(triggered()),this,SLOT(_editHex()));

    MENU_STATE menuState=getMenuState();

    QMenu contextMenu(this);
    QMenu menuGoTo(tr("Go to"),this);
    QMenu menuFind(tr("Find"),this);
    QMenu menuHex(tr("Hex"),this);
    QMenu menuSelect(tr("Select"),this);
    QMenu menuCopy(tr("Copy"),this);
    QMenu menuFollowIn(tr("Follow in"),this);
    QMenu menuEdit(tr("Edit"),this);

    menuGoTo.addAction(&actionGoToAddress);
    menuGoTo.addAction(&actionGoToOffset);
    menuGoTo.addAction(&actionGoToEntryPoint);

    contextMenu.addMenu(&menuGoTo);

    menuCopy.addAction(&actionCopyCursorAddress);
    menuCopy.addAction(&actionCopyCursorOffset);

    if(menuState.bSize)
    {
        menuCopy.addAction(&actionCopyAsHex);
    }

    contextMenu.addMenu(&menuCopy);

    menuFind.addAction(&actionFindString);
    menuFind.addAction(&actionFindSignature);
    menuFind.addAction(&actionFindValue);
    menuFind.addAction(&actionFindNext);

    contextMenu.addMenu(&menuFind);

    if(menuState.bSize)
    {
        contextMenu.addAction(&actionDumpToFile);
        contextMenu.addAction(&actionSignature);
        menuCopy.addAction(&actionCopyAsHex);

        menuHex.addAction(&actionHexSignature);

        contextMenu.addMenu(&menuHex);
    }

    if(menuState.bHex)
    {
        menuFollowIn.addAction(&actionHex);

        contextMenu.addMenu(&menuFollowIn);
    }

    menuEdit.setEnabled(!isReadonly());

    if(menuState.bSize)
    {
        menuEdit.addAction(&actionEditHex);

        contextMenu.addMenu(&menuEdit);
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
//    setColumnEnabled(COLUMN_OFFSET,!(g_options.bHideOffset));

    const QFontMetricsF fm(getTextFont());

    if(XBinary::getWidthModeFromSize(g_options.nInitAddress+getDataSize())==XBinary::MODE_64)
    {
        g_nAddressWidth=16;
        setColumnWidth(COLUMN_ADDRESS,2*getCharWidth()+fm.boundingRect("00000000:00000000").width());
//        setColumnWidth(COLUMN_OFFSET,2*getCharWidth()+fm.boundingRect("00000000:00000000").width());
    }
    else
    {
        g_nAddressWidth=8;
        setColumnWidth(COLUMN_ADDRESS,2*getCharWidth()+fm.boundingRect("0000:0000").width());
//        setColumnWidth(COLUMN_OFFSET,2*getCharWidth()+fm.boundingRect("0000:0000").width());
    }

    QString sBytes;

    for(qint32 i=0;i<g_nOpcodeSize;i++)
    {
        sBytes+="00";
    }

    setColumnWidth(COLUMN_BYTES,2*getCharWidth()+fm.boundingRect(sBytes).width());

//    setColumnWidth(COLUMN_BYTES,5*getCharWidth());

    setColumnWidth(COLUMN_ARROWS,5*getCharWidth());
    setColumnWidth(COLUMN_OPCODE,40*getCharWidth());
    setColumnWidth(COLUMN_COMMENT,60*getCharWidth());
}

void XDisasmView::registerShortcuts(bool bState)
{
    if(bState)
    {
        if(!shortCuts[SC_GOTOADDRESS])              shortCuts[SC_GOTOADDRESS]               =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ADDRESS),           this,SLOT(_goToAddressSlot()));
        if(!shortCuts[SC_GOTOOFFSET])               shortCuts[SC_GOTOOFFSET]                =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_OFFSET),            this,SLOT(_goToOffsetSlot()));
        if(!shortCuts[SC_GOTOENTRYPOINT])           shortCuts[SC_GOTOENTRYPOINT]            =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ENTRYPOINT),        this,SLOT(_goToEntryPointSlot()));
        if(!shortCuts[SC_DUMPTOFILE])               shortCuts[SC_DUMPTOFILE]                =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_DUMPTOFILE),             this,SLOT(_dumpToFileSlot()));
        if(!shortCuts[SC_SELECTALL])                shortCuts[SC_SELECTALL]                 =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SELECT_ALL),             this,SLOT(_selectAllSlot()));
        if(!shortCuts[SC_COPYASHEX])                shortCuts[SC_COPYASHEX]                 =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_HEX),               this,SLOT(_copyHexSlot()));
        if(!shortCuts[SC_COPYCURSORADDRESS])        shortCuts[SC_COPYCURSORADDRESS]         =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_ADDRESS),           this,SLOT(_copyAddressSlot()));
        if(!shortCuts[SC_COPYCURSOROFFSET])         shortCuts[SC_COPYCURSOROFFSET]          =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_OFFSET),            this,SLOT(_copyOffsetSlot()));
        if(!shortCuts[SC_FIND])                     shortCuts[SC_FIND]                      =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_STRING),            this,SLOT(_findStringSlot()));
        if(!shortCuts[SC_FINDNEXT])                 shortCuts[SC_FINDNEXT]                  =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_NEXT),              this,SLOT(_findNextSlot()));
        if(!shortCuts[SC_SIGNATURE])                shortCuts[SC_SIGNATURE]                 =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SIGNATURE),              this,SLOT(_signatureSlot()));
        if(!shortCuts[SC_HEXSIGNATURE])             shortCuts[SC_HEXSIGNATURE]              =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_HEX_SIGNATURE),          this,SLOT(_hexSignatureSlot()));
        if(!shortCuts[SC_FOLLOWIN_HEX])             shortCuts[SC_FOLLOWIN_HEX]              =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FOLLOWIN_HEX),           this,SLOT(_hexSlot()));
        if(!shortCuts[SC_EDIT_HEX])                 shortCuts[SC_EDIT_HEX]                  =new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_EDIT_HEX),               this,SLOT(_hexSlot()));
    }
    else
    {
        for(qint32 i=0;i<__SC_SIZE;i++)
        {
            if(shortCuts[i])
            {
                delete shortCuts[i];
                shortCuts[i]=nullptr;
            }
        }
    }
}

void XDisasmView::_headerClicked(qint32 nColumn)
{
    if(nColumn==COLUMN_ADDRESS)
    {
        if(getAddressMode()==MODE_ADDRESS)
        {
            setColumnTitle(COLUMN_ADDRESS,tr("Offset"));
            setAddressMode(MODE_OFFSET);
        }
        else if(getAddressMode()==MODE_OFFSET)
        {
            setColumnTitle(COLUMN_ADDRESS,tr("Relative address"));
            setAddressMode(MODE_RELADDRESS);
        }
        else if((getAddressMode()==MODE_RELADDRESS)||(getAddressMode()==MODE_THIS))
        {
            setColumnTitle(COLUMN_ADDRESS,tr("Address"));
            setAddressMode(MODE_ADDRESS);
        }

        adjust(true);
    }
    else if(nColumn==COLUMN_OPCODE)
    {
        if(g_modeOpcode==MODE_OPCODE_SYMBOLADDRESS)
        {
            setColumnTitle(COLUMN_OPCODE,tr("Opcode"));
            g_modeOpcode=MODE_OPCODE_ORIGINAL;
        }
        else if(g_modeOpcode==MODE_OPCODE_ORIGINAL)
        {
            setColumnTitle(COLUMN_OPCODE,QString("%1(%2)").arg(tr("Opcode"),tr("Symbol")));
            g_modeOpcode=MODE_OPCODE_SYMBOL;
        }
        else if(g_modeOpcode==MODE_OPCODE_SYMBOL)
        {
            setColumnTitle(COLUMN_OPCODE,QString("%1(%2)").arg(tr("Opcode"),tr("Address")));
            g_modeOpcode=MODE_OPCODE_ADDRESS;
        }
        else if(g_modeOpcode==MODE_OPCODE_ADDRESS)
        {
            setColumnTitle(COLUMN_OPCODE,QString("%1(%2->%3)").arg(tr("Opcode"),tr("Symbol"),tr("Address")));
            g_modeOpcode=MODE_OPCODE_SYMBOLADDRESS;
        }

        adjust(true);
    }
}

void XDisasmView::_cellDoubleClicked(qint32 nRow,qint32 nColumn)
{
    if(nColumn==COLUMN_ADDRESS)
    {
        setColumnTitle(COLUMN_ADDRESS,"");
        setAddressMode(MODE_THIS);

        if(nRow<g_listRecords.count())
        {
            g_nThisBase=XBinary::offsetToAddress(getMemoryMap(),g_listRecords.at(nRow).nOffset);
        }

        adjust(true);
    }
}

qint64 XDisasmView::getRecordSize(qint64 nOffset)
{
    qint64 nResult=1;

    QByteArray baData=read_array(nOffset,15); // TODO const

    DISASM_RESULT disasmResult=_disasm(baData.data(),baData.size(),0,MODE_ADDRESS);

    nResult=disasmResult.nSize;

    return nResult;
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

    dmds.setData(getDevice(),state.nSelectionOffset,getMemoryMap(),g_handle);

    dmds.setGlobal(getShortcuts(),getGlobalOptions());

    dmds.exec();
}

void XDisasmView::_hexSlot()
{
    if(g_options.bMenu_Hex)
    {
        STATE state=getState();

        emit showOffsetHex(state.nCursorOffset);
    }
}

void XDisasmView::_editHex()
{
    if(!isReadonly())
    {
        STATE state=getState();

        SubDevice sd(getDevice(),state.nSelectionOffset,state.nSelectionSize);

        if(sd.open(QIODevice::ReadWrite))
        {
            DialogHexEdit dialogHexEdit(this);

            dialogHexEdit.setGlobal(getShortcuts(),getGlobalOptions());

    //        connect(&dialogHexEdit,SIGNAL(changed()),this,SLOT(_setEdited()));

            dialogHexEdit.setData(&sd,state.nSelectionOffset);
            dialogHexEdit.setBackupDevice(getBackupDevice());

            dialogHexEdit.exec();

            _setEdited();

            sd.close();
        }
    }
}
