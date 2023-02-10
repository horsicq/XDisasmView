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
#include "xdisasmview.h"

XDisasmView::XDisasmView(QWidget *pParent) : XDeviceTableEditView(pParent)
{
    // TODO click on Address -> Offset
    g_handle = 0;

    g_nBytesProLine = 1;

    memset(shortCuts, 0, sizeof shortCuts);

    g_options = OPTIONS();
    g_disasmOptions = XCapstone::DISASM_OPTIONS();

    g_nAddressWidth = 8;
    g_nOpcodeSize = 16; // TODO Check
    g_nThisBase = 0;
    g_bIsAddressColon = false;
    g_bIsUppercase = false;
    g_bIsHighlight = false;
    g_syntax = XBinary::SYNTAX_DEFAULT;
    g_modeOpcode = MODE_OPCODE_SYMBOLADDRESS;

    addColumn("");  // Arrows
                    //    addColumn(tr("Address"),0,true);
    addColumn(tr("Address"), 0, true);
    //    addColumn(tr("Offset"));
    addColumn(tr("Bytes"));
    addColumn(QString("%1(%2->%3)").arg(tr("Opcode"), tr("Symbol"), tr("Address")), 0, true);  // TODO fix it in _adjustWindow
    addColumn(tr("Comment"));

    //    setLastColumnStretch(true);

    setTextFont(getMonoFont());

    setAddressMode(MODE_ADDRESS);

    _qTextOptions.setWrapMode(QTextOption::NoWrap);
}

XDisasmView::~XDisasmView()
{
    if (g_handle) {
        XCapstone::closeHandle(&g_handle);
    }
}

void XDisasmView::_adjustView()
{
    setTextFontFromOptions(XOptions::ID_DISASM_FONT);

    g_bIsHighlight = getGlobalOptions()->getValue(XOptions::ID_DISASM_HIGHLIGHT).toBool();
    g_bIsUppercase = getGlobalOptions()->getValue(XOptions::ID_DISASM_UPPERCASE).toBool();
    g_bIsAddressColon = getGlobalOptions()->getValue(XOptions::ID_DISASM_ADDRESSCOLON).toBool();

    g_syntax = XBinary::stringToSyntaxId(getGlobalOptions()->getValue(XOptions::ID_DISASM_SYNTAX).toString());

    g_mapOpcodeColorMap = getOpcodeColorMap(g_disasmMode, g_syntax);

    if (g_handle) {
        XCapstone::closeHandle(&g_handle);
    }

    XCapstone::openHandle(g_disasmMode, &g_handle, true, g_syntax);
}

void XDisasmView::adjustView()
{
    _adjustView();

    reload(true);
}

void XDisasmView::setData(QIODevice *pDevice, XDisasmView::OPTIONS options, bool bReload)
{
    g_options = options;

    g_listRecords.clear();

    setDevice(pDevice);
    setMemoryMap(g_options.memoryMapRegion);

    XBinary::DM disasmMode = XBinary::getDisasmMode(getMemoryMap());

    setMode(disasmMode);

    adjustColumns();
    adjustLineCount();
    adjustViewSize();

    if (options.nInitAddress != (XADDR)-1) {
//        qint64 nOffset = XBinary::addressToOffset(getMemoryMap(), options.nInitAddress);

//        if (nOffset == -1) {
//            nOffset = 0;
//        }

//        _goToViewOffset(nOffset, false, false, options.bAprox);
        goToAddress(options.nInitAddress, false, options.bAprox);
    }

    if (bReload) {
        reload(true);
    }
}

void XDisasmView::setMode(XBinary::DM disasmMode)
{
    g_disasmMode = disasmMode;

    if (getXInfoDB()) {
        getXInfoDB()->setDisasmMode(disasmMode);
    }

    _adjustView();
}

XBinary::DM XDisasmView::getMode()
{
    return g_disasmMode;
}

qint64 XDisasmView::getSelectionInitAddress()
{
    qint64 nResult = -1;

    qint64 nOffset = getSelectionInitOffset();

    if (nOffset != -1) {
        nResult = XBinary::offsetToAddress(getMemoryMap(), nOffset);
    }

    return nResult;
}

XDeviceTableView::DEVICESTATE XDisasmView::getDeviceState(bool bGlobalOffset)
{
    DEVICESTATE result = {};

    if (isAnalyzed()) {
        // TODO
        STATE state = getState();

        if (state.nSelectionViewSize == 0) {
            state.nSelectionViewSize = 1;
        }

        qint64 nShowOffset = getViewOffsetStart();

        XInfoDB::SHOWRECORD showRecordCursor = getXInfoDB()->getShowRecordByLine(state.nCursorViewOffset);
        XInfoDB::SHOWRECORD showRecordStartSelection = getXInfoDB()->getShowRecordByLine(state.nSelectionViewOffset);
        XInfoDB::SHOWRECORD showRecordEndSelection = getXInfoDB()->getShowRecordByLine(state.nSelectionViewOffset + state.nSelectionViewSize - 1);
        XInfoDB::SHOWRECORD showRecordShowStart = getXInfoDB()->getShowRecordByLine(nShowOffset);

        if (showRecordCursor.nOffset != -1 ) {
            result.nCursorOffset = showRecordCursor.nOffset;
        }

        XADDR nStartSelectionAddress = showRecordStartSelection.nAddress;
        qint64 nSelectionSize = showRecordEndSelection.nAddress + showRecordEndSelection.nSize - nStartSelectionAddress;

        if (!getXInfoDB()->isAnalyzedRegionVirtual(nStartSelectionAddress, nSelectionSize)) {
            result.nSelectionOffset = showRecordStartSelection.nOffset;
            result.nSelectionSize = nSelectionSize;
        }

        if (showRecordShowStart.nOffset == -1) {
            result.nShowOffset = getXInfoDB()->getShowRecordPrevOffsetByAddress(showRecordShowStart.nAddress);
        } else {
            result.nShowOffset = showRecordShowStart.nOffset;
        }

        if (bGlobalOffset) {
            XIODevice *pSubDevice = dynamic_cast<XIODevice *>(getDevice());

            if (pSubDevice) {
                qint64 nInitOffset = pSubDevice->getInitOffset();
                result.nSelectionOffset += nInitOffset;
                result.nCursorOffset += nInitOffset;
                result.nShowOffset += nInitOffset;
            }
        }
    } else {
        result = XDeviceTableView::getDeviceState(bGlobalOffset);
    }

    return result;
}

void XDisasmView::setDeviceState(DEVICESTATE deviceState, bool bGlobalOffset)
{
    if (isAnalyzed()) {
        if (bGlobalOffset) {
            XIODevice *pSubDevice = dynamic_cast<XIODevice *>(getDevice());

            if (pSubDevice) {
                qint64 nInitOffset = pSubDevice->getInitOffset();
                deviceState.nCursorOffset -= nInitOffset;
                deviceState.nSelectionOffset -= nInitOffset;
                deviceState.nShowOffset -= nInitOffset;
            }
        }

        qint64 nSelectionStart = getXInfoDB()->getShowRecordLineByOffset(deviceState.nSelectionOffset);
        qint64 nSelectionSize = getXInfoDB()->getShowRecordLineByOffset(deviceState.nSelectionOffset + deviceState.nSelectionSize) - nSelectionStart;
        qint64 nCursor = getXInfoDB()->getShowRecordLineByOffset(deviceState.nCursorOffset);
        qint64 nShowStart = getXInfoDB()->getShowRecordLineByOffset(deviceState.nShowOffset);

        _goToViewOffset(nShowStart);
        _initSelection(nSelectionStart, nSelectionSize);
        _setSelection(nSelectionStart, nSelectionSize);
        setCursorViewOffset(nCursor);

        adjust();
        viewport()->update();
    } else {
        XDeviceTableView::setDeviceState(deviceState, bGlobalOffset);
    }
}

qint64 XDisasmView::deviceOffsetToViewOffset(qint64 nOffset, bool bGlobalOffset)
{
    qint64 nResult = 0;

    if (isAnalyzed()) {
        qint64 _nOffset = XDeviceTableView::deviceOffsetToViewOffset(nOffset, bGlobalOffset);

        nResult = getXInfoDB()->getShowRecordLineByOffset(_nOffset);
    } else {
        nResult = XDeviceTableView::deviceOffsetToViewOffset(nOffset, bGlobalOffset);
    }

    return nResult;
}

qint64 XDisasmView::deviceSizeToViewSize(qint64 nOffset, qint64 nSize, bool bGlobalOffset)
{
    qint64 nResult = 0;

    if (isAnalyzed()) {
        qint64 _nOffsetStart = XDeviceTableView::deviceOffsetToViewOffset(nOffset, bGlobalOffset);
        qint64 _nOffsetEnd = XDeviceTableView::deviceOffsetToViewOffset(nOffset + nSize, bGlobalOffset);

        nResult = getXInfoDB()->getShowRecordLineByOffset(_nOffsetEnd) - getXInfoDB()->getShowRecordLineByOffset(_nOffsetStart);

        nResult = nResult +1;
    } else {
        nResult = XDeviceTableView::deviceOffsetToViewOffset(nOffset, nSize);
    }

    return nResult;
}

void XDisasmView::adjustLineCount()
{
    qint64 nTotalLineCount = 0;

    if (isAnalyzed()) {
        nTotalLineCount = getXInfoDB()->getShowRecordsCount();
    } else {
        nTotalLineCount = getViewSize() / g_nBytesProLine;

        if (nTotalLineCount > 1)  // TODO Check
        {
            nTotalLineCount--;
        }
    }

    setTotalLineCount(nTotalLineCount);
}

void XDisasmView::adjustViewSize()
{
    if (isAnalyzed()) {
        setViewSize(getXInfoDB()->getShowRecordsCount());
    } else {
        if (getDevice()) {
            setViewSize(getDevice()->size());
        }
    }
}

XCapstone::DISASM_RESULT XDisasmView::_disasm(XADDR nVirtualAddress, char *pData, qint32 nDataSize)
{
    XCapstone::DISASM_RESULT result = {};

    if (isAnalyzed()) {
        result = getXInfoDB()->dbToDisasm(nVirtualAddress);
        // TODO
    } else {
        result = XCapstone::disasm_ex(g_handle, g_disasmMode, pData, nDataSize, nVirtualAddress, g_disasmOptions);
    }

    if (g_bIsUppercase) {
        result.sMnemonic = result.sMnemonic.toUpper();
        result.sString = result.sString.toUpper();
    }

    return result;
}

QString XDisasmView::convertOpcodeString(XCapstone::DISASM_RESULT disasmResult)
{
    QString sResult = disasmResult.sString;

    if (getXInfoDB()) {
        if ((g_modeOpcode == MODE_OPCODE_SYMBOLADDRESS) || (g_modeOpcode == MODE_OPCODE_SYMBOL) || (g_modeOpcode == MODE_OPCODE_ADDRESS)) {
            XInfoDB::RI_TYPE riType = XInfoDB::RI_TYPE_SYMBOLADDRESS;

            if (g_modeOpcode == MODE_OPCODE_SYMBOLADDRESS) {
                riType = XInfoDB::RI_TYPE_SYMBOLADDRESS;
            } else if (g_modeOpcode == MODE_OPCODE_SYMBOL) {
                riType = XInfoDB::RI_TYPE_SYMBOL;
            } else if (g_modeOpcode == MODE_OPCODE_ADDRESS) {
                riType = XInfoDB::RI_TYPE_ADDRESS;
            }

            if (disasmResult.relType) {
                QString sReplace = XInfoDB::recordInfoToString(getXInfoDB()->getRecordInfoCache(disasmResult.nXrefToRelative), riType);

                if (sReplace != "") {
                    QString sOrigin = QString("0x%1").arg(QString::number(disasmResult.nXrefToRelative, 16));
                    sResult = disasmResult.sString.replace(sOrigin, sReplace);
                }
            }

            if (disasmResult.memType) {
                QString sReplace = XInfoDB::recordInfoToString(getXInfoDB()->getRecordInfoCache(disasmResult.nXrefToMemory), riType);

                if (sReplace != "") {
                    QString sOrigin = QString("0x%1").arg(QString::number(disasmResult.nXrefToMemory, 16));
                    sResult = disasmResult.sString.replace(sOrigin, sReplace);
                }
            }
        }
    }

    return sResult;
}

qint64 XDisasmView::getDisasmViewOffset(qint64 nViewOffset, qint64 nOldViewOffset)
{
    qint64 nResult = nViewOffset;

    if (nViewOffset != nOldViewOffset) {
        qint64 nStartOffset = nViewOffset - 5 * g_nOpcodeSize;
        qint64 nEndOffset = nViewOffset + 5 * g_nOpcodeSize;

        if (XBinary::getDisasmFamily(g_disasmMode) == XBinary::DMFAMILY_ARM)  // TODO Check
        {
            nStartOffset = S_ALIGN_DOWN(nStartOffset, 4);
        } else if (XBinary::getDisasmFamily(g_disasmMode) == XBinary::DMFAMILY_ARM64) {
            nStartOffset = S_ALIGN_DOWN(nStartOffset, 4);
        } else if (XBinary::getDisasmFamily(g_disasmMode) == XBinary::DMFAMILY_X86) {
            QByteArray _baData = read_array(nStartOffset, 2);

            if (*((quint16 *)_baData.data()) == 0)  // 0000
            {
                nStartOffset = S_ALIGN_DOWN(nStartOffset, 4);
            }
        }

        nStartOffset = qMax(nStartOffset, (qint64)0);
        nEndOffset = qMin(nEndOffset, getViewSize());

        if (nViewOffset > nOldViewOffset) {
            nStartOffset = qMax(nStartOffset, nOldViewOffset);
        }

        qint32 nSize = nEndOffset - nStartOffset;

        QByteArray baData = read_array(nStartOffset, nSize);

        nSize = baData.size();

        qint64 _nCurrentOffset = 0;

        // TODO nOffset<nOldOffset
        while (nSize > 0) {
            qint64 _nOffset = nStartOffset + _nCurrentOffset;

            XCapstone::DISASM_RESULT disasmResult = XCapstone::disasm_ex(g_handle, g_disasmMode, baData.data() + _nCurrentOffset, nSize, _nCurrentOffset, g_disasmOptions);

            if ((nViewOffset >= _nOffset) && (nViewOffset < _nOffset + disasmResult.nSize)) {
                if (_nOffset == nViewOffset) {
                    nResult = _nOffset;
                } else {
                    if (nOldViewOffset != -1) {
                        if (nViewOffset > nOldViewOffset) {
                            nResult = _nOffset + disasmResult.nSize;
                        } else {
                            nResult = _nOffset;
                        }
                    } else {
                        nResult = _nOffset;
                    }
                }

                break;
            }

            _nCurrentOffset += disasmResult.nSize;
            nSize -= disasmResult.nSize;
        }
    }

    return nResult;
}

XDisasmView::MENU_STATE XDisasmView::getMenuState()
{
    MENU_STATE result = {};

    DEVICESTATE state = getDeviceState();

    //    if(state.nCursorOffset!=XBinary::offsetToAddress(&(g_options.memoryMap),state.nCursorOffset))
    //    {
    //        result.bOffset=true;
    //    }

    if (state.nSelectionSize) {
        result.bSize = true;
    }

    if (g_options.bMenu_Hex) {
        result.bHex = true;
    }

    return result;
}

void XDisasmView::drawText(QPainter *pPainter, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight, QString sText, TEXT_OPTION *pTextOption)
{
    QRect rectText;

    rectText.setLeft(nLeft + getCharWidth());
    rectText.setTop(nTop + getLineDelta());
    rectText.setWidth(nWidth);
    rectText.setHeight(nHeight - getLineDelta());

    bool bSave = false;

    if ((pTextOption->bCursor) || (pTextOption->bCurrentIP)) {
        bSave = true;
    }

    if (bSave) {
        pPainter->save();
    }

    if ((pTextOption->bSelected) && (!pTextOption->bCursor) && (!pTextOption->bCurrentIP)) {
        pPainter->fillRect(nLeft, nTop, nWidth, nHeight, viewport()->palette().color(QPalette::Highlight));
    }

    if (pTextOption->bIsReplaced) {
        pPainter->fillRect(nLeft, nTop, nWidth, nHeight, QColor(Qt::red));
    } else if ((pTextOption->bCursor) || (pTextOption->bCurrentIP)) {
        pPainter->fillRect(nLeft, nTop, nWidth, nHeight, viewport()->palette().color(QPalette::WindowText));
        pPainter->setPen(viewport()->palette().color(QPalette::Base));
    }

    if (pTextOption->bHighlight) {
        drawDisasmText(pPainter, rectText, sText);
    } else {
        pPainter->drawText(rectText, sText, _qTextOptions);
    }

    if (bSave) {
        pPainter->restore();
    }
}

void XDisasmView::drawDisasmText(QPainter *pPainter, QRect rect, QString sText)
{
    QString sMnemonic = sText.section("|", 0, 0);
    QString sString = sText.section("|", 1, 1);

    QString _sMnenonic;

    if (g_bIsUppercase) {
        _sMnenonic = sMnemonic.toLower();
    } else {
        _sMnenonic = sMnemonic;
    }
    // TODO registers !!!
    if (g_bIsHighlight && g_mapOpcodeColorMap.contains(_sMnenonic)) {
        OPCODECOLOR opcodeColor = g_mapOpcodeColorMap.value(_sMnenonic);

        pPainter->save();

        QRect _rect = rect;

        _rect.setWidth(QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, sMnemonic).width());

        if (opcodeColor.colBackground.isValid()) {
            pPainter->fillRect(_rect, QBrush(opcodeColor.colBackground));
        }

        pPainter->setPen(opcodeColor.colText);
        pPainter->drawText(_rect, sMnemonic, _qTextOptions);

        pPainter->restore();

        if (sString != "") {
            QRect _rect = rect;
            _rect.setX(rect.x() + QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, sMnemonic + " ").width());

            pPainter->drawText(_rect, sString, _qTextOptions);
        }
    } else {
        QString sOpcode = sMnemonic;

        if (sString != "") {
            sOpcode += QString(" %1").arg(sString);
        }
        // TODO
        pPainter->drawText(rect, sOpcode, _qTextOptions);
    }
}

void XDisasmView::drawArrow(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond)
{
    pPainter->save();

    QPen pen;

    //blackPen.setWidth(10);
    if (bIsSelected) {
        pen.setColor(Qt::red);
    }

    pPainter->setPen(pen);

    QPolygonF arrowHead;
    qreal arrowSize = 8;

    QLineF line(pointEnd, pointStart);

    double angle = std::atan2(-line.dy(), line.dx());

    QPointF arrowP1 = line.p1() + QPointF(sin(angle + M_PI / 3) * arrowSize, cos(angle + M_PI / 3) * arrowSize);
    QPointF arrowP2 = line.p1() + QPointF(sin(angle + M_PI - M_PI / 3) * arrowSize, cos(angle + M_PI - M_PI / 3) * arrowSize);

    arrowHead << line.p1() << arrowP1 << arrowP2;

    pPainter->drawPolygon(arrowHead);

    pPainter->restore();

    drawLine(pPainter, pointStart, pointEnd, bIsSelected, bIsCond);
}

void XDisasmView::drawLine(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond)
{
    pPainter->save();

    QPen pen;

    //blackPen.setWidth(10);
    if (bIsSelected) {
        pen.setColor(Qt::red);
    }

    if (bIsCond) {
        pen.setStyle(Qt::DotLine);
    }

    pPainter->setPen(pen);
    pPainter->drawLine(pointStart, pointEnd);

    pPainter->restore();
}

QMap<QString, XDisasmView::OPCODECOLOR> XDisasmView::getOpcodeColorMap(XBinary::DM disasmMode, XBinary::SYNTAX syntax)
{
    QMap<QString, OPCODECOLOR> mapResult;

    if (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_X86) {
        OPCODECOLOR colorCALL = getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_CALL);
        OPCODECOLOR colorJCC = getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_JCC);
        OPCODECOLOR colorRET = getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_RET);
        OPCODECOLOR colorPUSH = getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_PUSH);
        OPCODECOLOR colorPOP = getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_POP);
        OPCODECOLOR colorNOP = getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_NOP);
        OPCODECOLOR colorJMP = getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_JMP);
        OPCODECOLOR colorINT3 = getOpcodeColor(XOptions::ID_DISASM_COLOR_X86_INT3);

        if ((syntax == XBinary::SYNTAX_DEFAULT) || (syntax == XBinary::SYNTAX_INTEL) || (syntax == XBinary::SYNTAX_MASM)) {
            mapResult.insert("call", colorCALL);
            mapResult.insert("ret", colorRET);
            mapResult.insert("push", colorPUSH);
            mapResult.insert("pop", colorPOP);
            mapResult.insert("nop", colorNOP);
            mapResult.insert("jmp", colorJMP);
            mapResult.insert("int3", colorINT3);
            mapResult.insert("je", colorJCC);
            mapResult.insert("jne", colorJCC);
            mapResult.insert("jz", colorJCC);
            mapResult.insert("jnz", colorJCC);
            mapResult.insert("ja", colorJCC);
            mapResult.insert("jc", colorJCC);
        } else if (syntax == XBinary::SYNTAX_ATT) {
            {
                mapResult.insert("callw", colorCALL);
                mapResult.insert("calll", colorCALL);
                mapResult.insert("callq", colorCALL);
            }
            {
                mapResult.insert("retw", colorRET);
                mapResult.insert("retl", colorRET);
                mapResult.insert("retq", colorRET);
            }
            {
                mapResult.insert("pushw", colorPUSH);
                mapResult.insert("pushl", colorPUSH);
                mapResult.insert("pushq", colorPUSH);
            }
            {
                mapResult.insert("popw", colorPUSH);
                mapResult.insert("popl", colorPUSH);
                mapResult.insert("popq", colorPUSH);
            }

            mapResult.insert("nop", colorNOP);
            mapResult.insert("jmp", colorJMP);
            mapResult.insert("int3", colorINT3);
            mapResult.insert("je", colorJCC);
            mapResult.insert("jne", colorJCC);
            mapResult.insert("jz", colorJCC);
            mapResult.insert("jnz", colorJCC);
            mapResult.insert("ja", colorJCC);
            mapResult.insert("jc", colorJCC);
        }
    } else if ((XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_ARM) || (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_ARM64)) {
        OPCODECOLOR colorBL = getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_BL);
        OPCODECOLOR colorRET = getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_RET);
        OPCODECOLOR colorPUSH = getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_PUSH);
        OPCODECOLOR colorPOP = getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_POP);

        mapResult.insert("bl", colorBL);
        mapResult.insert("ret", colorRET);
        mapResult.insert("push", colorPUSH);
        mapResult.insert("pop", colorPOP);
    }

    return mapResult;
}

XDisasmView::OPCODECOLOR XDisasmView::getOpcodeColor(XOptions::ID id)
{
    OPCODECOLOR result = {};

    QString sCode = getGlobalOptions()->getValue(id).toString();
    QString sTextCode = sCode.section("|", 0, 0);
    QString sBackgroundCode = sCode.section("|", 1, 1);

    if (sTextCode != "") {
        result.colText.setNamedColor(sTextCode);
    }

    if (sBackgroundCode != "") {
        result.colBackground.setNamedColor(sBackgroundCode);
    }

    return result;
}

XDisasmView::RECORD XDisasmView::_getRecordByViewOffset(QList<RECORD> *pListRecord, qint64 nViewOffset)
{
    RECORD result = {};

    qint32 nNumberOfRecords = pListRecord->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if (pListRecord->at(i).nViewOffset == nViewOffset) {
            result = pListRecord->at(i);

            break;
        }
    }

    return result;
}

XDisasmView::RECORD XDisasmView::_getRecordByVirtualAddress(QList<RECORD> *pListRecord, XADDR nVirtualAddress)
{
    RECORD result = {};

    qint32 nNumberOfRecords = pListRecord->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if (pListRecord->at(i).nVirtualAddress == nVirtualAddress) {
            result = pListRecord->at(i);

            break;
        }
    }

    return result;
}

XAbstractTableView::OS XDisasmView::cursorPositionToOS(XAbstractTableView::CURSOR_POSITION cursorPosition)
{
    OS osResult = {};
    osResult.nViewOffset = -1;

    if ((cursorPosition.bIsValid) && (cursorPosition.ptype == PT_CELL)) {
        if (cursorPosition.nRow < g_listRecords.count()) {
            qint64 nBlockOffset = g_listRecords.at(cursorPosition.nRow).nViewOffset;
            qint64 nBlockSize = 0;

            if (isAnalyzed()) {
                nBlockSize = 1;
            } else {
                nBlockSize = g_listRecords.at(cursorPosition.nRow).disasmResult.nSize;
            }

            if (cursorPosition.nColumn == COLUMN_LOCATION) {
                osResult.nViewOffset = nBlockOffset;
                osResult.nSize = nBlockSize;
            }
            //            else if(cursorPosition.nColumn==COLUMN_OFFSET)
            //            {
            //                osResult.nOffset=nBlockOffset;
            //                osResult.nSize=nBlockSize;
            //            }
            else if (cursorPosition.nColumn == COLUMN_BYTES) {
                // TODO
                osResult.nViewOffset = nBlockOffset;
                osResult.nSize = nBlockSize;
            } else if (cursorPosition.nColumn == COLUMN_OPCODE) {
                osResult.nViewOffset = nBlockOffset;
                osResult.nSize = nBlockSize;
            } else if (cursorPosition.nColumn == COLUMN_COMMENT) {
                osResult.nViewOffset = nBlockOffset;
                osResult.nSize = nBlockSize;
            }
        } else {
            if (!isViewOffsetValid(osResult.nViewOffset)) {
                osResult.nViewOffset = getViewSize();  // TODO Check
                osResult.nSize = 0;
            }
        }
    }

    return osResult;
}

void XDisasmView::updateData()
{
    g_listRecords.clear();
    //    g_listArrows.clear();

    if (getDevice()) {
        XBinary::MODE mode = XBinary::getWidthModeFromByteSize(g_nAddressWidth);

        qint64 nBlockViewOffset = getViewOffsetStart();
        qint32 nNumberLinesProPage = getLinesProPage();
        qint64 nCurrentViewOffset = nBlockViewOffset;

        QList<XInfoDB::SHOWRECORD> listShowRecords;

        if (isAnalyzed()) {
            listShowRecords = getXInfoDB()->getShowRecords(nBlockViewOffset, nNumberLinesProPage);
        }

        for (qint32 i = 0; i < nNumberLinesProPage; i++) {
            if (nCurrentViewOffset < getViewSize()) {
                qint64 nViewSize = 0;

                RECORD record = {};

                record.nViewOffset = nCurrentViewOffset;

                qint32 nBufferSize = 0;

                QByteArray baBuffer; // mb TODO fix buffer

                if (isAnalyzed()) {
                    XInfoDB::SHOWRECORD showRecord = listShowRecords.at(i);
                    record.nVirtualAddress = showRecord.nAddress;
                    record.nDeviceOffset = showRecord.nOffset;

                    record.disasmResult = _disasm(record.nVirtualAddress, nullptr, 0);

                    nViewSize = 1;

                    if (record.nDeviceOffset != -1) {
                        nBufferSize = record.disasmResult.nSize;
                        baBuffer = read_array(record.nDeviceOffset, qMin(nBufferSize, g_nOpcodeSize));

                        if((record.disasmResult.sMnemonic == "db") && (record.disasmResult.sString == "")) {
                            record.disasmResult.sString = XBinary::getDataString(baBuffer.data(), baBuffer.size());
                        }
                    }
                } else {
                    record.nDeviceOffset = nCurrentViewOffset;
                    record.nVirtualAddress = XBinary::offsetToAddress(getMemoryMap(), nCurrentViewOffset);

                    nBufferSize = qMin(g_nOpcodeSize, qint32(getViewSize() - record.nDeviceOffset));

                    baBuffer = read_array(record.nDeviceOffset, nBufferSize);
                    nBufferSize = baBuffer.size();

                    if (nBufferSize == 0) {
                        break;
                    }

                    record.disasmResult = _disasm(record.nVirtualAddress, baBuffer.data(), baBuffer.size());

                    nBufferSize = record.disasmResult.nSize;
                    baBuffer.resize(nBufferSize);

                    nViewSize = nBufferSize;
                }

                if (nViewSize == 0) {
                    break;
                }

                record.bIsReplaced = isReplaced(record.nDeviceOffset, nBufferSize);
                record.sBytes = baBuffer.toHex().data();

                XADDR _nCurrent = 0;

                if (getAddressMode() == MODE_THIS) {
                    _nCurrent = record.nVirtualAddress;

                    qint64 nDelta = (qint64)_nCurrent - (qint64)g_nThisBase;

                    record.sLocation = XBinary::thisToString(nDelta);
                } else {
                    if (getAddressMode() == MODE_ADDRESS) {
                        _nCurrent = record.nVirtualAddress;
                    } else if (getAddressMode() == MODE_OFFSET) {
                        _nCurrent = record.nDeviceOffset;
                    } else if (getAddressMode() == MODE_RELADDRESS) {
                        _nCurrent = XBinary::addressToRelAddress(getMemoryMap(), record.nVirtualAddress);
                    }

                    //                record.sOffset=XBinary::valueToHexColon(mode,nCurrentOffset);

                    if (_nCurrent == (XADDR)-1) {
                        _nCurrent = nCurrentViewOffset;
                    }

                    if (g_bIsAddressColon) {
                        record.sLocation = XBinary::valueToHexColon(mode, _nCurrent);
                    } else {
                        record.sLocation = XBinary::valueToHex(mode, _nCurrent);
                    }

                    if (getAddressMode() == MODE_RELADDRESS) {
                        QString sPrefix;
                        QString sSymbol;

                        if (record.nDeviceOffset != -1) {
                            sPrefix = XBinary::getMemoryRecordInfoByOffset(getMemoryMap(), record.nDeviceOffset);
                        } else if (record.nVirtualAddress != -1) {
                            sPrefix = XBinary::getMemoryRecordInfoByAddress(getMemoryMap(), record.nVirtualAddress);
                        }

                        if (record.nVirtualAddress != -1) {
                            if (isAnalyzed()) {
                                sSymbol = getXInfoDB()->getSymbolStringByAddress(record.nVirtualAddress);
                            }
                        }

                        if (sPrefix != "") {
                            record.sLocation = QString("%1:%2").arg(sPrefix, record.sLocation);
                        }

                        if (sSymbol != "") {
                            record.sLocation = QString("%1.%2").arg(record.sLocation, sSymbol);
                        }
                    }
                }

                g_listRecords.append(record);

                nCurrentViewOffset += nViewSize;
            } else {
                break;
            }
        }

        qint32 nNumberOfRecords = g_listRecords.count();

        if (nNumberOfRecords) {
            for (qint32 i = 0; i < nNumberOfRecords; i++) {
                if (g_listRecords.at(i).disasmResult.relType) {
                    XADDR nXrefTo = g_listRecords.at(i).disasmResult.nXrefToRelative;
                    XADDR nCurrentAddress = g_listRecords.at(i).nVirtualAddress;

                    qint32 nStart = 0;
                    qint32 nEnd = nNumberOfRecords - 1;
                    qint32 nMaxLevel = 0;

                    if (nCurrentAddress > nXrefTo) {
                        nEnd = i;

                        g_listRecords[i].nArraySize = nEnd;

                        for (qint32 j = i; j >= nStart; j--) {
                            nMaxLevel = qMax(g_listRecords.at(j).nMaxLevel, nMaxLevel);

                            if ((nXrefTo >= g_listRecords.at(j).nVirtualAddress) && (nXrefTo < (g_listRecords.at(j).nVirtualAddress + g_listRecords.at(j).disasmResult.nSize))) {
                                nStart = j;
                                g_listRecords[i].nArraySize = nEnd - nStart;
                                g_listRecords[i].bIsEnd = true;

                                break;
                            }
                        }

                        g_listRecords[i].array = ARRAY_UP;
                    } else if (nCurrentAddress < nXrefTo) {
                        nStart = i;

                        g_listRecords[i].nArraySize = nNumberOfRecords - nStart;

                        for (qint32 j = i; j <= nEnd; j++) {
                            nMaxLevel = qMax(g_listRecords.at(j).nMaxLevel, nMaxLevel);

                            if ((nXrefTo >= g_listRecords.at(j).nVirtualAddress) && (nXrefTo < (g_listRecords.at(j).nVirtualAddress + g_listRecords.at(j).disasmResult.nSize))) {
                                nEnd = j;
                                g_listRecords[i].nArraySize = nEnd - nStart;
                                g_listRecords[i].bIsEnd = true;

                                break;
                            }
                        }

                        g_listRecords[i].array = ARRAY_DOWN;
                    }

                    g_listRecords[i].nArrayLevel = nMaxLevel + 1;

                    for (qint32 j = nStart; j <= nEnd; j++) {
                        g_listRecords[j].nMaxLevel = nMaxLevel + 1;
                    }
                }
            }
        }

        setCurrentBlock(nBlockViewOffset, (nCurrentViewOffset - nBlockViewOffset));
    }
}

void XDisasmView::paintColumn(QPainter *pPainter, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{
    Q_UNUSED(nHeight)

    if (nColumn == COLUMN_ARROWS) {
        qint32 nNumberOfRecords = g_listRecords.count();

        if (nNumberOfRecords) {
            for (qint32 i = 0; i < nNumberOfRecords; i++) {

                if (g_listRecords.at(i).disasmResult.relType != XCapstone::RELTYPE_NONE) {

                    bool bIsSelected = isViewOffsetSelected(g_listRecords.at(i).nViewOffset);
                    bool bIsCond = (g_listRecords.at(i).disasmResult.relType == XCapstone::RELTYPE_JMPCOND);

                    QPointF point1;
                    point1.setX(nLeft + nWidth);
                    point1.setY(nTop + ((i + 0.5) * getLineHeight()));

                    QPointF point2;
                    point2.setX((nLeft + nWidth) - getCharWidth() * (g_listRecords.at(i).nArrayLevel));
                    point2.setY(point1.y());

                    QPointF point3;

                    point3.setX(point2.x());

                    qint32 nDelta = getLineHeight() * g_listRecords.at(i).nArraySize;

                    if (!(g_listRecords.at(i).bIsEnd)) {
                        nDelta += 0.5 * getLineHeight();
                    }

                    if (g_listRecords.at(i).array == ARRAY_UP) {
                        point3.setY(point1.y() - nDelta);
                    } else if (g_listRecords.at(i).array == ARRAY_DOWN) {
                        point3.setY(point1.y() + nDelta);
                    }

                    drawLine(pPainter, point1, point2, bIsSelected, bIsCond);

                    if (g_listRecords.at(i).bIsEnd) {
                        drawLine(pPainter, point2, point3, bIsSelected, bIsCond);

                        QPointF point4;
                        point4.setX(point1.x());
                        point4.setY(point3.y());

                        drawArrow(pPainter, point3, point4, bIsSelected, bIsCond);
                    } else {
                        drawArrow(pPainter, point2, point3, bIsSelected, bIsCond);
                    }
                }
            }
        }
    }
}

void XDisasmView::paintCell(QPainter *pPainter, qint32 nRow, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{
    qint32 nNumberOfRows = g_listRecords.count();

    qint64 nCursorOffset = getState().nCursorViewOffset;

    if (nRow < nNumberOfRows) {
        qint64 nOffset = g_listRecords.at(nRow).nViewOffset;

        TEXT_OPTION textOption = {};
        textOption.bSelected = isViewOffsetSelected(nOffset);

        textOption.bCursor = (nOffset == nCursorOffset) && (nColumn == COLUMN_BYTES);
        textOption.bIsReplaced = ((g_listRecords.at(nRow).bIsReplaced) && (nColumn == COLUMN_LOCATION));

        if (getXInfoDB()) {
#ifdef USE_XPROCESS
            XADDR nAddress = g_listRecords.at(nRow).disasmResult.nAddress;
            XADDR nCurrentIP = getXInfoDB()->getCurrentInstructionPointerCache();

            textOption.bCurrentIP = ((nCurrentIP != -1) && (nAddress == nCurrentIP) && (nColumn == COLUMN_LOCATION));
#endif
        }

        if (nColumn == COLUMN_ARROWS) {
            // TODO
        } else if (nColumn == COLUMN_LOCATION) {
            drawText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).sLocation, &textOption);
        }
        //        else if(nColumn==COLUMN_OFFSET)
        //        {
        //            drawText(pPainter,nLeft,nTop,nWidth,nHeight,g_listRecords.at(nRow).sOffset,&textOption);
        //        }
        else if (nColumn == COLUMN_BYTES) {
            drawText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).sBytes, &textOption);
        } else if (nColumn == COLUMN_OPCODE) {
            QString sOpcode = QString("%1|%2").arg(g_listRecords.at(nRow).disasmResult.sMnemonic, convertOpcodeString(g_listRecords.at(nRow).disasmResult));

            textOption.bHighlight = true;
            drawText(pPainter, nLeft, nTop, nWidth, nHeight, sOpcode, &textOption);
        } else if (nColumn == COLUMN_COMMENT) {
            drawText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).sComment, &textOption);
        }
    }
}

void XDisasmView::contextMenu(const QPoint &pos)
{
    if (isContextMenuEnable()) {
        QAction actionGoToAddress(tr("Address"), this);
        actionGoToAddress.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ADDRESS));
        connect(&actionGoToAddress, SIGNAL(triggered()), this, SLOT(_goToAddressSlot()));

        QAction actionGoToOffset(tr("Offset"), this);
        actionGoToOffset.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_OFFSET));
        connect(&actionGoToOffset, SIGNAL(triggered()), this, SLOT(_goToOffsetSlot()));

        QAction actionGoToEntryPoint(tr("Entry point"), this);
        actionGoToEntryPoint.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ENTRYPOINT));
        connect(&actionGoToEntryPoint, SIGNAL(triggered()), this, SLOT(_goToEntryPointSlot()));

        QAction actionGoXrefRelative("", this);
        connect(&actionGoXrefRelative, SIGNAL(triggered()), this, SLOT(_goToXrefSlot()));

        QAction actionGoXrefMemory("", this);
        connect(&actionGoXrefMemory, SIGNAL(triggered()), this, SLOT(_goToXrefSlot()));

        QAction actionDumpToFile(tr("Dump to file"), this);
        actionDumpToFile.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_DUMPTOFILE));
        connect(&actionDumpToFile, SIGNAL(triggered()), this, SLOT(_dumpToFileSlot()));

        QAction actionHexSignature(tr("Hex signature"), this);
        actionHexSignature.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_HEX_SIGNATURE));
        connect(&actionHexSignature, SIGNAL(triggered()), this, SLOT(_hexSignatureSlot()));

        QAction actionSignature(tr("Signature"), this);
        actionSignature.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SIGNATURE));
        connect(&actionSignature, SIGNAL(triggered()), this, SLOT(_signatureSlot()));

        QAction actionFindString(tr("String"), this);
        actionFindString.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_STRING));
        connect(&actionFindString, SIGNAL(triggered()), this, SLOT(_findStringSlot()));

        QAction actionFindSignature(tr("Signature"), this);
        actionFindSignature.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_SIGNATURE));
        connect(&actionFindSignature, SIGNAL(triggered()), this, SLOT(_findSignatureSlot()));

        QAction actionFindValue(tr("Value"), this);
        actionFindValue.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_VALUE));
        connect(&actionFindValue, SIGNAL(triggered()), this, SLOT(_findValueSlot()));

        QAction actionFindNext(tr("Find next"), this);
        actionFindNext.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_NEXT));
        connect(&actionFindNext, SIGNAL(triggered()), this, SLOT(_findNextSlot()));

        QAction actionSelectAll(tr("Select all"), this);
        actionSelectAll.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SELECT_ALL));
        connect(&actionSelectAll, SIGNAL(triggered()), this, SLOT(_selectAllSlot()));

        QAction actionCopyAsData(tr("Data"), this);
        actionCopyAsData.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_DATA));
        connect(&actionCopyAsData, SIGNAL(triggered()), this, SLOT(_copyDataSlot()));

        QAction actionCopyCursorOffset(tr("Offset"), this);
        actionCopyCursorOffset.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_OFFSET));
        connect(&actionCopyCursorOffset, SIGNAL(triggered()), this, SLOT(_copyOffsetSlot()));

        QAction actionCopyCursorAddress(tr("Address"), this);
        actionCopyCursorAddress.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_ADDRESS));
        connect(&actionCopyCursorAddress, SIGNAL(triggered()), this, SLOT(_copyAddressSlot()));

        QAction actionCopyLocation("", this);
        connect(&actionCopyLocation, SIGNAL(triggered()), this, SLOT(_copyValueSlot()));

        QAction actionCopyBytes("", this);
        connect(&actionCopyBytes, SIGNAL(triggered()), this, SLOT(_copyValueSlot()));

        QAction actionCopyOpcode("", this);
        connect(&actionCopyOpcode, SIGNAL(triggered()), this, SLOT(_copyValueSlot()));

        QAction actionCopyComment("", this);
        connect(&actionCopyComment, SIGNAL(triggered()), this, SLOT(_copyValueSlot()));

        QAction actionHex(tr("Hex"), this);
        actionHex.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FOLLOWIN_HEX));
        connect(&actionHex, SIGNAL(triggered()), this, SLOT(_hexSlot()));

        QAction actionEditHex(tr("Hex"), this);
        actionEditHex.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_EDIT_HEX));
        connect(&actionEditHex, SIGNAL(triggered()), this, SLOT(_editHex()));

        MENU_STATE mstate = getMenuState();

        QMenu contextMenu(this);
        QMenu menuGoTo(tr("Go to"), this);
        QMenu menuFind(tr("Find"), this);
        QMenu menuHex(tr("Hex"), this);
        QMenu menuSelect(tr("Select"), this);
        QMenu menuCopy(tr("Copy"), this);
        QMenu menuFollowIn(tr("Follow in"), this);
        QMenu menuEdit(tr("Edit"), this);

        menuGoTo.addAction(&actionGoToAddress);
        menuGoTo.addAction(&actionGoToOffset);
        menuGoTo.addAction(&actionGoToEntryPoint);

        // TODO go to address
        STATE state = getState();

        XDisasmView::RECORD record = _getRecordByViewOffset(&g_listRecords, state.nSelectionViewOffset);

        if (record.disasmResult.relType || record.disasmResult.memType) {
            menuGoTo.addSeparator();

            if (record.disasmResult.relType) {
                actionGoXrefRelative.setText(QString("0x%1").arg(record.disasmResult.nXrefToRelative, 0, 16));
                actionGoXrefRelative.setProperty("ADDRESS", record.disasmResult.nXrefToRelative);
                menuGoTo.addAction(&actionGoXrefRelative);
            }

            if (record.disasmResult.memType) {
                actionGoXrefMemory.setText(QString("0x%1").arg(record.disasmResult.nXrefToMemory, 0, 16));
                actionGoXrefMemory.setProperty("ADDRESS", record.disasmResult.nXrefToMemory);
                menuGoTo.addAction(&actionGoXrefMemory);
            }
        }

        contextMenu.addMenu(&menuGoTo);

        menuCopy.addAction(&actionCopyCursorAddress);
        menuCopy.addAction(&actionCopyCursorOffset);

        if (mstate.bSize) {
            menuCopy.addAction(&actionCopyAsData);
        }

        RECORD _record = _getRecordByViewOffset(&g_listRecords, state.nCursorViewOffset);

        if ((_record.sLocation != "") || (_record.sBytes != "") || (_record.disasmResult.sMnemonic != "") || (_record.sComment != "")) {
            menuCopy.addSeparator();

            if (_record.sLocation != "") {
                actionCopyLocation.setText(_record.sLocation);
                actionCopyLocation.setProperty("VALUE", _record.sLocation);
                menuCopy.addAction(&actionCopyLocation);
            }

            if (_record.sBytes != "") {
                actionCopyBytes.setText(_record.sBytes);
                actionCopyBytes.setProperty("VALUE", _record.sBytes);
                menuCopy.addAction(&actionCopyBytes);
            }

            if (_record.disasmResult.sMnemonic != "") {
                QString sString = _record.disasmResult.sMnemonic;

                if (_record.disasmResult.sString != "") {
                    sString.append(QString(" %1").arg(convertOpcodeString(_record.disasmResult)));
                }

                actionCopyOpcode.setText(sString);
                actionCopyOpcode.setProperty("VALUE", sString);
                menuCopy.addAction(&actionCopyOpcode);
            }

            if (_record.sComment != "") {
                actionCopyComment.setText(_record.sComment);
                actionCopyComment.setProperty("VALUE", _record.sComment);
                menuCopy.addAction(&actionCopyComment);
            }
        }

        contextMenu.addMenu(&menuCopy);

        menuFind.addAction(&actionFindString);
        menuFind.addAction(&actionFindSignature);
        menuFind.addAction(&actionFindValue);
        menuFind.addAction(&actionFindNext);

        contextMenu.addMenu(&menuFind);

        if (mstate.bSize) {
            contextMenu.addAction(&actionDumpToFile);
            contextMenu.addAction(&actionSignature);

            menuHex.addAction(&actionHexSignature);

            contextMenu.addMenu(&menuHex);
        }

        if (mstate.bHex) {
            menuFollowIn.addAction(&actionHex);

            contextMenu.addMenu(&menuFollowIn);
        }

        menuEdit.setEnabled(!isReadonly());

        if (mstate.bSize) {
            menuEdit.addAction(&actionEditHex);

            contextMenu.addMenu(&menuEdit);
        }

        menuSelect.addAction(&actionSelectAll);
        contextMenu.addMenu(&menuSelect);

        // TODO reset select

        contextMenu.exec(pos);
    }
}

void XDisasmView::wheelEvent(QWheelEvent *pEvent)
{
    XAbstractTableView::wheelEvent(pEvent);
}

void XDisasmView::keyPressEvent(QKeyEvent *pEvent)
{
    XAbstractTableView::keyPressEvent(pEvent);
}

qint64 XDisasmView::getCurrentLineFromScroll()
{
    qint64 nResult = 0;

    if (isAnalyzed()) {
        nResult = verticalScrollBar()->value();
    } else {
        qint32 nValue = verticalScrollBar()->value();

        qint64 nMaxValue = getMaxScrollValue() * g_nBytesProLine;

        if (getViewSize() > nMaxValue) {
            if (nValue == getMaxScrollValue()) {
                nResult = getViewSize() - g_nBytesProLine;
            } else {
                nResult = ((double)nValue / (double)getMaxScrollValue()) * getViewSize();
            }
        } else {
            nResult = (qint64)nValue * g_nBytesProLine;
        }

        qint64 _nResult = getDisasmViewOffset(nResult, getViewOffsetStart());

        if (_nResult != nResult) {
            nResult = _nResult;

            setCurrentViewOffsetToScroll(nResult);
        }
    }

    return nResult;
}

void XDisasmView::setCurrentViewOffsetToScroll(qint64 nViewOffset)
{
    setViewOffsetStart(nViewOffset);

    qint32 nValue = 0;

    if (getViewSize() > (getMaxScrollValue() * g_nBytesProLine)) {
        if (nViewOffset == getViewSize() - g_nBytesProLine) {
            nValue = getMaxScrollValue();
        } else {
            nValue = ((double)(nViewOffset) / ((double)getViewSize())) * (double)getMaxScrollValue();
        }
    } else {
        nValue = (nViewOffset) / g_nBytesProLine;
    }

    verticalScrollBar()->setValue(nValue);

    adjust(true);  // TODO mb Remove
}

void XDisasmView::adjustColumns()
{
    //    setColumnEnabled(COLUMN_OFFSET,!(g_options.bHideOffset));

    const QFontMetricsF fm(getTextFont());

    if (XBinary::getWidthModeFromSize(g_options.nInitAddress + getViewSize()) == XBinary::MODE_64) {
        g_nAddressWidth = 16;
        setColumnWidth(COLUMN_LOCATION, 2 * getCharWidth() + fm.boundingRect("00000000:00000000").width());
        //        setColumnWidth(COLUMN_OFFSET,2*getCharWidth()+fm.boundingRect("00000000:00000000").width());
    } else {
        g_nAddressWidth = 8;
        setColumnWidth(COLUMN_LOCATION, 2 * getCharWidth() + fm.boundingRect("0000:0000").width());
        //        setColumnWidth(COLUMN_OFFSET,2*getCharWidth()+fm.boundingRect("0000:0000").width());
    }

    QString sBytes;

    for (qint32 i = 0; i < g_nOpcodeSize; i++) {
        sBytes += "00";
    }

    setColumnWidth(COLUMN_BYTES, 2 * getCharWidth() + fm.boundingRect(sBytes).width());

    //    setColumnWidth(COLUMN_BYTES,5*getCharWidth());

    setColumnWidth(COLUMN_ARROWS, 5 * getCharWidth());
    setColumnWidth(COLUMN_OPCODE, 40 * getCharWidth());
    setColumnWidth(COLUMN_COMMENT, 60 * getCharWidth());
}

void XDisasmView::registerShortcuts(bool bState)
{
    if (bState) {
        if (!shortCuts[SC_GOTOADDRESS]) shortCuts[SC_GOTOADDRESS] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ADDRESS), this, SLOT(_goToAddressSlot()));
        if (!shortCuts[SC_GOTOOFFSET]) shortCuts[SC_GOTOOFFSET] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_OFFSET), this, SLOT(_goToOffsetSlot()));
        if (!shortCuts[SC_GOTOENTRYPOINT])
            shortCuts[SC_GOTOENTRYPOINT] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ENTRYPOINT), this, SLOT(_goToEntryPointSlot()));
        if (!shortCuts[SC_DUMPTOFILE]) shortCuts[SC_DUMPTOFILE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_DUMPTOFILE), this, SLOT(_dumpToFileSlot()));
        if (!shortCuts[SC_SELECTALL]) shortCuts[SC_SELECTALL] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SELECT_ALL), this, SLOT(_selectAllSlot()));
        if (!shortCuts[SC_COPYDATA]) shortCuts[SC_COPYDATA] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_DATA), this, SLOT(_copyDataSlot()));
        if (!shortCuts[SC_COPYADDRESS])
            shortCuts[SC_COPYADDRESS] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_ADDRESS), this, SLOT(_copyAddressSlot()));
        if (!shortCuts[SC_COPYOFFSET])
            shortCuts[SC_COPYOFFSET] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_OFFSET), this, SLOT(_copyOffsetSlot()));
        if (!shortCuts[SC_FIND_STRING]) shortCuts[SC_FIND_STRING] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_STRING), this, SLOT(_findStringSlot()));
        if (!shortCuts[SC_FIND_SIGNATURE])
            shortCuts[SC_FIND_SIGNATURE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_SIGNATURE), this, SLOT(_findSignatureSlot()));
        if (!shortCuts[SC_FIND_VALUE]) shortCuts[SC_FIND_VALUE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_VALUE), this, SLOT(_findValueSlot()));
        if (!shortCuts[SC_FINDNEXT]) shortCuts[SC_FINDNEXT] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_NEXT), this, SLOT(_findNextSlot()));
        if (!shortCuts[SC_SIGNATURE]) shortCuts[SC_SIGNATURE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SIGNATURE), this, SLOT(_signatureSlot()));
        if (!shortCuts[SC_HEXSIGNATURE])
            shortCuts[SC_HEXSIGNATURE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_HEX_SIGNATURE), this, SLOT(_hexSignatureSlot()));
        if (!shortCuts[SC_FOLLOWIN_HEX]) shortCuts[SC_FOLLOWIN_HEX] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FOLLOWIN_HEX), this, SLOT(_hexSlot()));
        if (!shortCuts[SC_EDIT_HEX]) shortCuts[SC_EDIT_HEX] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_EDIT_HEX), this, SLOT(_editHex()));
    } else {
        for (qint32 i = 0; i < __SC_SIZE; i++) {
            if (shortCuts[i]) {
                delete shortCuts[i];
                shortCuts[i] = nullptr;
            }
        }
    }
}

void XDisasmView::_headerClicked(qint32 nColumn)
{
    if (nColumn == COLUMN_LOCATION) {
        if (getAddressMode() == MODE_ADDRESS) {
            setColumnTitle(COLUMN_LOCATION, tr("Offset"));
            setAddressMode(MODE_OFFSET);
        } else if (getAddressMode() == MODE_OFFSET) {
            setColumnTitle(COLUMN_LOCATION, tr("Relative address"));
            setAddressMode(MODE_RELADDRESS);
        } else if ((getAddressMode() == MODE_RELADDRESS) || (getAddressMode() == MODE_THIS)) {
            setColumnTitle(COLUMN_LOCATION, tr("Address"));
            setAddressMode(MODE_ADDRESS);
        }

        adjust(true);
    } else if (nColumn == COLUMN_OPCODE) {
        if (g_modeOpcode == MODE_OPCODE_SYMBOLADDRESS) {
            setColumnTitle(COLUMN_OPCODE, tr("Opcode"));
            g_modeOpcode = MODE_OPCODE_ORIGINAL;
        } else if (g_modeOpcode == MODE_OPCODE_ORIGINAL) {
            setColumnTitle(COLUMN_OPCODE, QString("%1(%2)").arg(tr("Opcode"), tr("Symbol")));
            g_modeOpcode = MODE_OPCODE_SYMBOL;
        } else if (g_modeOpcode == MODE_OPCODE_SYMBOL) {
            setColumnTitle(COLUMN_OPCODE, QString("%1(%2)").arg(tr("Opcode"), tr("Address")));
            g_modeOpcode = MODE_OPCODE_ADDRESS;
        } else if (g_modeOpcode == MODE_OPCODE_ADDRESS) {
            setColumnTitle(COLUMN_OPCODE, QString("%1(%2->%3)").arg(tr("Opcode"), tr("Symbol"), tr("Address")));
            g_modeOpcode = MODE_OPCODE_SYMBOLADDRESS;
        }

        adjust(true);
    }
}

void XDisasmView::_cellDoubleClicked(qint32 nRow, qint32 nColumn)
{
    if (nColumn == COLUMN_LOCATION) {
        setColumnTitle(COLUMN_LOCATION, "");
        setAddressMode(MODE_THIS);

        if (nRow < g_listRecords.count()) {
            g_nThisBase = XBinary::offsetToAddress(getMemoryMap(), g_listRecords.at(nRow).nViewOffset);
        }

        adjust(true);
    }
}

qint64 XDisasmView::getRecordSize(qint64 nViewOffset)
{
    // TODO analyzed
    qint64 nResult = 1;

    if (!isAnalyzed()) {
        QByteArray baData = read_array(nViewOffset, g_nOpcodeSize);

        XCapstone::DISASM_RESULT disasmResult = XCapstone::disasm_ex(g_handle, g_disasmMode, baData.data(), baData.size(), 0, g_disasmOptions);

        nResult = disasmResult.nSize;
    }

    return nResult;
}

qint64 XDisasmView::getFixViewOffset(qint64 nViewOffset)
{
    qint64 nResult = 0;

    if (isAnalyzed()) {
        nResult = nViewOffset;
    } else {
        nResult = getDisasmViewOffset(nViewOffset, -1);
    }

    return nResult;
}

void XDisasmView::_goToEntryPointSlot()
{
    goToAddress(g_options.nEntryPointAddress);
    setFocus();
    viewport()->update();
}

void XDisasmView::_goToXrefSlot()
{
    QAction *pAction = qobject_cast<QAction *>(sender());

    if (pAction) {
        XADDR nAddress = pAction->property("ADDRESS").toULongLong();

        goToAddress(nAddress);
        setFocus();
        viewport()->update();
    }
}

void XDisasmView::_signatureSlot()
{
    DEVICESTATE state = getDeviceState();

    DialogMultiDisasmSignature dmds(this);

    dmds.setData(getDevice(), state.nSelectionOffset, getMemoryMap(), g_handle);

    dmds.setGlobal(getShortcuts(), getGlobalOptions());

    dmds.exec();
}

void XDisasmView::_hexSlot()
{
    if (g_options.bMenu_Hex) {
        emit showOffsetHex(getDeviceState().nCursorOffset);
    }
}
