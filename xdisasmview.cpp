/* Copyright (c) 2020-2024 hors<horsicq@gmail.com>
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

    memset(g_shortCuts, 0, sizeof g_shortCuts);

    g_options = OPTIONS();
    g_disasmOptions = XCapstone::DISASM_OPTIONS();

    g_nAddressWidth = 8;
    g_nOpcodeSize = 16;  // TODO Check
    g_nThisBaseVirtualAddress = 0;
    g_nThisBaseDeviceOffset = 0;
    g_bIsLocationColon = false;
    g_bIsHighlight = false;
    g_syntax = XBinary::SYNTAX_DEFAULT;
    // g_opcodeMode = OPCODEMODE_SYMBOLADDRESS;
    //    g_bytesMode = BYTESMODE_RAW;

    addColumn("");  // Arrows
    addColumn("");  // Breakpoints
                    //    addColumn(tr("Address"),0,true);
    addColumn(tr("Address"), 0, true);
    addColumn("");  // Info
    addColumn(tr("Bytes"), 0, true);
    addColumn(tr("Opcode"), 0, true);  // TODO fix it in _adjustWindow
    addColumn(tr("Comment"));

    //    setLastColumnStretch(true);

    setTextFont(XOptions::getMonoFont());
    setLocationMode(LOCMODE_ADDRESS);

    _qTextOptions.setWrapMode(QTextOption::NoWrap);

    setVerticalLinesVisible(false);
}

XDisasmView::~XDisasmView()
{
    if (g_handle) {
        XCapstone::closeHandle(&g_handle);
    }
}

void XDisasmView::adjustView()
{
    setTextFontFromOptions(XOptions::ID_DISASM_FONT);

    g_bIsHighlight = getGlobalOptions()->getValue(XOptions::ID_DISASM_HIGHLIGHT).toBool();
    g_disasmOptions.bIsUppercase = getGlobalOptions()->getValue(XOptions::ID_DISASM_UPPERCASE).toBool();
    g_bIsLocationColon = getGlobalOptions()->getValue(XOptions::ID_DISASM_LOCATIONCOLON).toBool();

    g_syntax = XBinary::stringToSyntaxId(getGlobalOptions()->getValue(XOptions::ID_DISASM_SYNTAX).toString());
    g_dmFamily = XBinary::getDisasmFamily(g_options.disasmMode);

    g_mapColors = getColorRecordsMap();

    // TODO BP color

    if (g_handle) {
        XCapstone::closeHandle(&g_handle);
    }

    XCapstone::openHandle(g_options.disasmMode, &g_handle, true, g_syntax);

    viewport()->update();
}

void XDisasmView::_adjustView()
{
    adjustView();

    reload(true);
}

void XDisasmView::setData(QIODevice *pDevice, const OPTIONS &options, bool bReload)
{
    g_options = options;

    g_listRecords.clear();

    setDevice(pDevice);
    setMemoryMap(g_options.memoryMapRegion);

    if (g_options.disasmMode == XBinary::DM_UNKNOWN) {
        g_options.disasmMode = XBinary::getDisasmMode(getMemoryMap());
    }

    adjustView();

    adjustColumns();
    adjustScrollCount();

    if (options.nInitAddress != (XADDR)-1) {
        //        qint64 nOffset = XBinary::addressToOffset(getMemoryMap(), options.nInitAddress);

        //        if (nOffset == -1) {
        //            nOffset = 0;
        //        }

        //        _goToViewPos(nOffset, false, false, options.bAprox);
        goToAddress(options.nInitAddress, false, options.bAprox, false);
        //        addVisited(options.nInitAddress);
    } else {
        //        addVisited(0);
    }

    if (bReload) {
        reload(true);
    }
}

XDisasmView::OPTIONS XDisasmView::getOptions()
{
    return g_options;
}

XBinary::DM XDisasmView::getDisasmMode()
{
    return g_options.disasmMode;
}

XADDR XDisasmView::getSelectionInitAddress()
{
    XADDR nResult = -1;

    qint64 nOffset = getSelectionInitOffset();

    if (nOffset != -1) {
        nResult = XBinary::offsetToAddress(getMemoryMap(), nOffset);
    }

    return nResult;
}

XDeviceTableView::DEVICESTATE XDisasmView::getDeviceState(bool bGlobalOffset)
{
    //    DEVICESTATE result = {};

    //    if (isAnalyzed()) {
    //        // TODO
    //        STATE state = getState();

    //        if (state.nSelectionViewSize == 0) {
    //            state.nSelectionViewSize = 1;
    //        }

    //        qint64 nShowOffset = getViewPosStart();  // TODO convert

    //        //        XInfoDB::SHOWRECORD showRecordCursor = getXInfoDB()->getShowRecordByLine(state.nCursorViewPos);
    //        XInfoDB::SHOWRECORD showRecordStartSelection = getXInfoDB()->getShowRecordByLine(state.nSelectionViewPos);
    //        XInfoDB::SHOWRECORD showRecordEndSelection = getXInfoDB()->getShowRecordByLine(state.nSelectionViewPos + state.nSelectionViewSize - 1);
    //        XInfoDB::SHOWRECORD showRecordShowStart = getXInfoDB()->getShowRecordByLine(nShowOffset);

    //        //        if (showRecordCursor.nOffset != -1 ) {
    //        //            result.nCursorOffset = showRecordCursor.nOffset;
    //        //        }

    //        XADDR nStartSelectionAddress = showRecordStartSelection.nAddress;
    //        qint64 nSelectionSize = showRecordEndSelection.nAddress + showRecordEndSelection.nSize - nStartSelectionAddress;

    //        if (!getXInfoDB()->isAnalyzedRegionVirtual(nStartSelectionAddress, nSelectionSize)) {
    //            result.nSelectionLocation = showRecordStartSelection.nOffset;
    //            result.nSelectionSize = nSelectionSize;
    //        }

    //        if (showRecordShowStart.nOffset == -1) {
    //            result.nShowLocation = getXInfoDB()->getShowRecordPrevOffsetByAddress(showRecordShowStart.nAddress);
    //        } else {
    //            result.nShowLocation = showRecordShowStart.nOffset;
    //        }

    //        if (bGlobalOffset) {
    //            XIODevice *pSubDevice = dynamic_cast<XIODevice *>(getDevice());

    //            if (pSubDevice) {
    //                quint64 nInitOffset = pSubDevice->getInitLocation();
    //                result.nSelectionLocation += nInitOffset;
    //                //                result.nCursorOffset += nInitOffset;
    //                result.nShowLocation += nInitOffset;
    //            }
    //        }
    //    } else {
    //        DEVICESTATE result = {};
    //        STATE state = getState();

    //        result.nSelectionLocation = viewPosToDeviceOffset(state.nSelectionViewPos, bGlobalOffset);
    //        result.nSelectionSize = state.nSelectionViewSize; // TODO Check
    //        result.nShowLocation = viewPosToDeviceOffset(state.nSelectionViewPos, bGlobalOffset);

    //        return result;
    //    }

    //    return result;
    DEVICESTATE result = {};
    STATE state = getState();

    result.nSelectionDeviceOffset = viewPosToDeviceOffset(state.nSelectionViewPos, bGlobalOffset);
    result.nStartDeviceOffset = viewPosToDeviceOffset(getViewPosStart(), bGlobalOffset);

    if (result.nSelectionDeviceOffset != (quint64)-1) {
        result.nSelectionSize = state.nSelectionViewSize;
        // TODO if virtual region return 0
    }

    return result;
}

void XDisasmView::setDeviceState(const DEVICESTATE &deviceState, bool bGlobalOffset)
{
    _goToViewPos(deviceOffsetToViewPos(deviceState.nStartDeviceOffset, bGlobalOffset));
    _initSetSelection(deviceOffsetToViewPos(deviceState.nSelectionDeviceOffset, bGlobalOffset), deviceState.nSelectionSize);

    adjust();
    viewport()->update();
}

qint64 XDisasmView::deviceOffsetToViewPos(qint64 nOffset, bool bGlobalOffset)
{
    qint64 nResult = 0;

    //    if (isAnalyzed()) {
    //        qint64 _nOffset = XDeviceTableView::deviceOffsetToViewPos(nOffset, bGlobalOffset);

    //        nResult = getXInfoDB()->getShowRecordLineByOffset(_nOffset);
    //    } else {
    //        nResult = XDeviceTableView::deviceOffsetToViewPos(nOffset, bGlobalOffset);
    //    }
    qint64 _nOffset = XDeviceTableView::deviceOffsetToViewPos(nOffset, bGlobalOffset);

    VIEWSTRUCT viewStruct = _getViewStructByOffset(_nOffset);

    if (viewStruct.nSize) {
        nResult = viewStruct.nViewPos + (nOffset - viewStruct.nOffset);
    }

    return nResult;
}

qint64 XDisasmView::deviceSizeToViewSize(qint64 nOffset, qint64 nSize, bool bGlobalOffset)
{
    Q_UNUSED(bGlobalOffset)

    qint64 nResult = 0;

    //    if (isAnalyzed()) {
    //        qint64 _nOffsetStart = XDeviceTableView::deviceOffsetToViewPos(nOffset, bGlobalOffset);
    //        qint64 _nOffsetEnd = XDeviceTableView::deviceOffsetToViewPos(nOffset + nSize, bGlobalOffset);

    //        nResult = getXInfoDB()->getShowRecordLineByOffset(_nOffsetEnd) - getXInfoDB()->getShowRecordLineByOffset(_nOffsetStart);

    //        nResult = nResult + 1;
    //    } else {
    //        nResult = XDeviceTableView::deviceOffsetToViewPos(nOffset, nSize);
    //    }

    nResult = XDeviceTableView::deviceSizeToViewSize(nOffset, nSize);

    return nResult;
}

qint64 XDisasmView::viewPosToDeviceOffset(qint64 nViewPos, bool bGlobalOffset)
{
    qint64 nResult = -1;

    VIEWSTRUCT viewStruct = _getViewStructByViewPos(nViewPos);

    if (viewStruct.nSize && (viewStruct.nOffset != -1)) {
        nResult = viewStruct.nOffset + (nViewPos - viewStruct.nViewPos);
        nResult = XDeviceTableView::viewPosToDeviceOffset(nResult, bGlobalOffset);
    }

    return nResult;
}

void XDisasmView::adjustScrollCount()
{
    //    qint64 nTotalLineCount = 0;

    //    if (isAnalyzed()) {
    //        nTotalLineCount = getXInfoDB()->getShowRecordsCount();
    //    } else {
    //        nTotalLineCount = getViewSize() / g_nBytesProLine;

    //        if (nTotalLineCount > 1)  // TODO Check
    //        {
    //            nTotalLineCount--;
    //        }
    //    }

    //    setTotalLineCount(nTotalLineCount);

    g_listViewStruct.clear();
    // TODO XInfoDB

    qint32 nNumberOfRecords = getMemoryMap()->listRecords.count();

    qint64 nScrollStart = 0;
    qint64 nViewPos = 0;

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        VIEWSTRUCT record = {};
        record.nAddress = getMemoryMap()->listRecords.at(i).nAddress;
        record.nOffset = getMemoryMap()->listRecords.at(i).nOffset;
        record.nSize = getMemoryMap()->listRecords.at(i).nSize;
        record.nScrollStart = nScrollStart;
        record.nViewPos = nViewPos;
        record.nScrollCount = record.nSize;

        bool bAdd = true;
        // TODO XInfoDB

        if ((getMemoryMap()->fileType == XBinary::FT_MACHO32) || (getMemoryMap()->fileType == XBinary::FT_MACHO64)) {
            if (i == 0) {
                bAdd = false;  // DO NOT add zeropage
            }
        }

        if (bAdd) {
            nScrollStart += record.nScrollCount;
            nViewPos += record.nSize;

            g_listViewStruct.append(record);
        }
    }

    setViewSize(nViewPos);
    setTotalScrollCount(nScrollStart);
}

qint64 XDisasmView::getViewSizeByViewPos(qint64 nViewPos)
{
    // TODO
    // Check always return 1
    qint64 nResult = 0;

    QByteArray baData = read_array(nViewPos, g_nOpcodeSize);

    XCapstone::DISASM_RESULT disasmResult = XCapstone::disasm_ex(g_handle, g_options.disasmMode, g_syntax, baData.data(), baData.size(), 0, g_disasmOptions);

    nResult = disasmResult.nSize;

    return nResult;
}

qint64 XDisasmView::addressToViewPos(XADDR nAddress)
{
    qint64 nResult = 0;

    //    if (!isAnalyzed()) {
    //        nResult = XDeviceTableView::addressToViewPos(nAddress);
    //    } else {
    //        nResult = getXInfoDB()->getShowRecordLineByAddress(nAddress);
    //    }
    VIEWSTRUCT viewStruct = _getViewStructByAddress(nAddress);

    if (viewStruct.nSize) {
        nResult = viewStruct.nViewPos + (nAddress - viewStruct.nAddress);
    }

    return nResult;
}

QString XDisasmView::convertOpcodeString(const XCapstone::DISASM_RESULT &disasmResult)
{
    QString sResult;

    if (getXInfoDB()) {
        // if ((g_opcodeMode == OPCODEMODE_SYMBOLADDRESS) || (g_opcodeMode == OPCODEMODE_SYMBOL) || (g_opcodeMode == OPCODEMODE_ADDRESS)) {
        //     XInfoDB::RI_TYPE riType = XInfoDB::RI_TYPE_SYMBOLADDRESS;

        //     if (g_opcodeMode == OPCODEMODE_SYMBOLADDRESS) {
        //         riType = XInfoDB::RI_TYPE_SYMBOLADDRESS;
        //     } else if (g_opcodeMode == OPCODEMODE_SYMBOL) {
        //         riType = XInfoDB::RI_TYPE_SYMBOL;
        //     } else if (g_opcodeMode == OPCODEMODE_ADDRESS) {
        //         riType = XInfoDB::RI_TYPE_ADDRESS;
        //     }

        //     sResult = getXInfoDB()->convertOpcodeString(disasmResult, g_options.disasmMode, g_syntax, riType, g_disasmOptions);
        // }
        XInfoDB::RI_TYPE riType = XInfoDB::RI_TYPE_SYMBOLADDRESS;
        sResult = getXInfoDB()->convertOpcodeString(disasmResult, g_options.disasmMode, g_syntax, riType, g_disasmOptions);
    }

    if (sResult == "") {
        sResult = disasmResult.sString;
    }

    return sResult;
}

qint64 XDisasmView::getDisasmViewPos(qint64 nViewPos, qint64 nOldViewPos)
{
    qint64 nResult = nViewPos;

    if (nViewPos != nOldViewPos) {
        if (nOldViewPos == -1) {
            nOldViewPos = nViewPos;
        }

        bool bSuccess = false;

        VIEWSTRUCT viewStruct = _getViewStructByViewPos(nViewPos);
        //        VIEWSTRUCT viewStructOld = _getViewStructByViewPos(nOldViewPos);

        XADDR nAddress = 0;
        //        XADDR nAddressOld = 0;
        qint64 nOffset = 0;
        //        qint64 nOffsetOld = 0;

        if (viewStruct.nAddress != (XADDR)-1) {
            nAddress = viewStruct.nAddress + (nViewPos - viewStruct.nViewPos);
        }

        if (viewStruct.nOffset != -1) {
            nOffset = viewStruct.nOffset + (nViewPos - viewStruct.nViewPos);
        }

        //        if (viewStructOld.nAddress != -1) {
        //            nAddressOld = viewStructOld.nAddress + (nOldViewPos - viewStructOld.nViewPos);
        //        }

        //        if (viewStructOld.nOffset != -1) {
        //            nOffsetOld = viewStructOld.nOffset + (nOldViewPos - viewStructOld.nViewPos);
        //        }

        if (!bSuccess) {
            if (getXInfoDB()) {
                XInfoDB::SHOWRECORD showRecord = {};

                if (nAddress != (XADDR)-1) {
                    showRecord = getXInfoDB()->getShowRecordByAddress(nAddress, true);
                }
                // TODO offset !!!

                if (showRecord.bValid) {
                    if (nViewPos > nOldViewPos) {
                        if (nAddress != (XADDR)-1) {
                            nResult = _getViewPosByAddress(showRecord.nAddress + showRecord.nSize);
                        }
                    } else {
                        if (nAddress != (XADDR)-1) {
                            nResult = _getViewPosByAddress(showRecord.nAddress);
                        }
                    }

                    bSuccess = true;
                }
            }
        }

        if ((!bSuccess) && (nOffset != -1)) {
            qint64 nStartOffset = 0;
            qint64 nEndOffset = 0;

            nStartOffset = nOffset - 5 * g_nOpcodeSize;
            nEndOffset = nOffset + 5 * g_nOpcodeSize;

            if (g_dmFamily == XBinary::DMFAMILY_ARM)  // TODO Check
            {
                nStartOffset = S_ALIGN_DOWN(nStartOffset, 4);
            } else if (g_dmFamily == XBinary::DMFAMILY_ARM64) {
                nStartOffset = S_ALIGN_DOWN(nStartOffset, 4);
            } else if (g_dmFamily == XBinary::DMFAMILY_M68K) {
                nStartOffset = S_ALIGN_DOWN(nStartOffset, 2);
            } else if (g_dmFamily == XBinary::DMFAMILY_X86) {
                //                QByteArray _baData = read_array(nStartOffset, 2);  // TODO optimize

                //                if (*((quint16 *)_baData.data()) == 0)  // 0000
                //                {
                //                    nStartOffset = S_ALIGN_DOWN(nStartOffset, 4);
                //                }
                nStartOffset = S_ALIGN_DOWN(nStartOffset, 4);
            }

            nStartOffset = qMax(nStartOffset, viewStruct.nOffset);
            nEndOffset = qMin(nEndOffset, viewStruct.nOffset + viewStruct.nSize);

            qint32 nSize = nEndOffset - nStartOffset;

            QByteArray baData = read_array(nStartOffset, nSize);

            nSize = baData.size();

            qint64 _nCurrentOffset = 0;
            qint64 _nResult = 0;

            while (nSize > 0) {
                qint64 _nOffset = nStartOffset + _nCurrentOffset;

                XCapstone::DISASM_RESULT disasmResult =
                    XCapstone::disasm_ex(g_handle, g_options.disasmMode, g_syntax, baData.data() + _nCurrentOffset, nSize, _nCurrentOffset, g_disasmOptions);

                if ((nOffset >= _nOffset) && (nOffset < _nOffset + disasmResult.nSize)) {
                    if (_nOffset == nOffset) {
                        _nResult = _nOffset;
                    } else {
                        if (nViewPos > nOldViewPos) {
                            _nResult = _nOffset + disasmResult.nSize;
                        } else {
                            _nResult = _nOffset;
                        }
                    }
                    nResult = viewStruct.nViewPos + (_nResult - viewStruct.nOffset);

                    break;
                }

                _nCurrentOffset += disasmResult.nSize;
                nSize -= disasmResult.nSize;
            }
        }
    }

    return nResult;
}

XDisasmView::MENU_STATE XDisasmView::getMenuState()
{
    MENU_STATE result = {};

    DEVICESTATE deviceState = getDeviceState();
    STATE state = getState();

    //    if(state.nCursorOffset!=XBinary::offsetToAddress(&(g_options.memoryMap),state.nCursorOffset))
    //    {
    //        result.bOffset=true;
    //    }

    if (deviceState.nSelectionSize) {
        result.bPhysicalSize = true;
    }
    if (state.nSelectionViewSize) {
        result.bSize = true;
    }

    if (g_options.bMenu_Hex) {
        result.bHex = true;
    }

    return result;
}

void XDisasmView::drawText(QPainter *pPainter, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight, const QString &sText, TEXT_OPTION *pTextOption)
{
    QRect rectText;

    rectText.setLeft(nLeft + getCharWidth());
    rectText.setTop(nTop + getLineDelta());
    rectText.setWidth(nWidth);
    rectText.setHeight(nHeight - getLineDelta());

    bool bSave = false;

    //    if (pTextOption->bIsCursor) {
    //        bSave = true;
    //    }

    if (bSave) {
        pPainter->save();
    }

    if (pTextOption->bIsSelected) {
        pPainter->fillRect(nLeft, nTop, nWidth, nHeight, pTextOption->colSelected);
    }

    if (pTextOption->bIsBreakpoint) {
        pPainter->fillRect(nLeft, nTop, nWidth, nHeight, pTextOption->colBreakpoint);
    } else if (pTextOption->bIsAnalysed) {
        pPainter->fillRect(nLeft, nTop, nWidth, nHeight, pTextOption->colAnalyzed);
    } /*else if (pTextOption->bIsCursor) {
        pPainter->fillRect(nLeft, nTop, nWidth, nHeight, viewport()->palette().color(QPalette::WindowText));
        pPainter->setPen(viewport()->palette().color(QPalette::Base));
    }*/

    if (pTextOption->bASMHighlight) {
        drawAsmText(pPainter, rectText, sText);
    } else {
        pPainter->drawText(rectText, sText, _qTextOptions);
    }

    if (bSave) {
        pPainter->restore();
    }
}

void XDisasmView::drawAsmText(QPainter *pPainter, const QRect &rect, const QString &sText)
{
    QString sMnemonic = sText.section("|", 0, 0);
    QString sString = sText.section("|", 1, 1);

    // TODO registers !!!

    if (g_bIsHighlight) {
        COLOR_RECORD opcodeColorNOP = {};

        QRect _rectMnemonic = rect;
        _rectMnemonic.setWidth(QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, sMnemonic).width());

        COLOR_RECORD opcodeColor = getOpcodeColor(sMnemonic.toLower());

        bool bIsNOP = false;

        if (XCapstone::isNopOpcode(g_dmFamily, sMnemonic.toLower(), g_syntax)) {
            opcodeColorNOP = opcodeColor;
            bIsNOP = true;
        }

        drawColorText(pPainter, _rectMnemonic, sMnemonic, opcodeColor);

        if (sString != "") {
            QRect _rectString = rect;
            _rectString.setX(rect.x() + QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, sMnemonic + " ").width());

            if (bIsNOP) {
                drawColorText(pPainter, _rectString, sString, opcodeColorNOP);
            } else {
                drawArg(pPainter, _rectString, sString);
            }
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

void XDisasmView::drawColorText(QPainter *pPainter, const QRect &rect, const QString &sText, const COLOR_RECORD &colorRecord)
{
    if (colorRecord.colBackground.isValid() || colorRecord.colMain.isValid()) {
        pPainter->save();

        QRect _rectString = rect;
        _rectString.setWidth(QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, sText).width());

        if (colorRecord.colBackground.isValid()) {
            pPainter->fillRect(_rectString, QBrush(colorRecord.colBackground));
        }

        if (colorRecord.colMain.isValid()) {
            pPainter->setPen(colorRecord.colMain);
        }

        pPainter->drawText(_rectString, sText, _qTextOptions);

        pPainter->restore();
    } else {
        pPainter->drawText(rect, sText, _qTextOptions);
    }
}

void XDisasmView::drawArg(QPainter *pPainter, const QRect &rect, const QString &sText)
{
    QList<XCapstone::OPERANDPART> listParts = XCapstone::getOperandParts(g_dmFamily, sText, g_syntax);

    qint32 nNumberOfParts = listParts.count();

    QRect _rect = rect;

    for (qint32 i = 0; i < nNumberOfParts; i++) {
        QString sString = listParts.at(i).sString;

        qint32 nWidth = QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, sString).width();
        _rect.setWidth(nWidth);

        if (listParts.at(i).bIsMain) {
            COLOR_RECORD colorOperand = getOperandColor(sString.toLower());
            drawColorText(pPainter, _rect, sString, colorOperand);
        } else {
            pPainter->drawText(_rect, sString, _qTextOptions);
        }

        _rect.setX(_rect.x() + nWidth);
    }
}

void XDisasmView::drawArrowHead(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond)
{
    pPainter->save();

    QPen pen;

    if (bIsSelected) {
        pen.setColor(g_mapColors.value(XOptions::ID_DISASM_COLOR_ARROWS_SELECTED).colMain);
    } else {
        pen.setColor(g_mapColors.value(XOptions::ID_DISASM_COLOR_ARROWS).colMain);
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

    drawArrowLine(pPainter, pointStart, pointEnd, bIsSelected, bIsCond);
}

void XDisasmView::drawArrowLine(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond)
{
    pPainter->save();

    QPen pen;

    if (bIsSelected) {
        pen.setColor(g_mapColors.value(XOptions::ID_DISASM_COLOR_ARROWS_SELECTED).colMain);
    } else {
        pen.setColor(g_mapColors.value(XOptions::ID_DISASM_COLOR_ARROWS).colMain);
    }

    if (bIsCond) {
        pen.setStyle(Qt::DotLine);
    }

    pPainter->setPen(pen);
    pPainter->drawLine(pointStart, pointEnd);

    pPainter->restore();
}

QMap<XOptions::ID, XDisasmView::COLOR_RECORD> XDisasmView::getColorRecordsMap()
{
    QMap<XOptions::ID, COLOR_RECORD> mapResult;

    mapResult.insert(XOptions::ID_DISASM_COLOR_ARROWS, getColorRecord(XOptions::ID_DISASM_COLOR_ARROWS));
    mapResult.insert(XOptions::ID_DISASM_COLOR_ARROWS_SELECTED, getColorRecord(XOptions::ID_DISASM_COLOR_ARROWS_SELECTED));
    mapResult.insert(XOptions::ID_DISASM_COLOR_REGS, getColorRecord(XOptions::ID_DISASM_COLOR_REGS));
    mapResult.insert(XOptions::ID_DISASM_COLOR_NUMBERS, getColorRecord(XOptions::ID_DISASM_COLOR_NUMBERS));
    mapResult.insert(XOptions::ID_DISASM_COLOR_OPCODE, getColorRecord(XOptions::ID_DISASM_COLOR_OPCODE));
    mapResult.insert(XOptions::ID_DISASM_COLOR_REFS, getColorRecord(XOptions::ID_DISASM_COLOR_REFS));

    if (g_dmFamily == XBinary::DMFAMILY_X86) {
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_GENERAL, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_GENERAL));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_STACK, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_STACK));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_SEGMENT, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_SEGMENT));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_DEBUG, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_DEBUG));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_IP, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_IP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_FLAGS, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_FLAGS));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_FPU, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_FPU));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_XMM, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_XMM));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_CALL, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_CALL));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_COND_JMP, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_COND_JMP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_RET, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_RET));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_PUSH, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_PUSH));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_POP, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_POP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_NOP, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_NOP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_JMP, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_JMP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_INT3, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_INT3));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_SYSCALL, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_SYSCALL));
        // TODO
    } else if ((g_dmFamily == XBinary::DMFAMILY_ARM) || (g_dmFamily == XBinary::DMFAMILY_ARM64)) {
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_REGS_GENERAL, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_REGS_GENERAL));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_B, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_B));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_BL, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_BL));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_RET, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_RET));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_PUSH, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_PUSH));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_POP, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_POP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_NOP, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_NOP));
    }

    return mapResult;
}

XDisasmView::COLOR_RECORD XDisasmView::getColorRecord(XOptions::ID id)
{
    COLOR_RECORD result = {};

    QString sCode = getGlobalOptions()->getValue(id).toString();
    QString sColorCode = sCode.section("|", 0, 0);
    QString sBackgroundCode = sCode.section("|", 1, 1);

    if (sColorCode != "") {
        result.colMain.setNamedColor(sColorCode);
    }

    if (sBackgroundCode != "") {
        result.colBackground.setNamedColor(sBackgroundCode);
    }

    return result;
}

XDisasmView::COLOR_RECORD XDisasmView::getOpcodeColor(const QString &sOpcode)
{
    COLOR_RECORD result = {};

    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_OPCODE);

    if (g_dmFamily == XBinary::DMFAMILY_X86) {
        if (XCapstone::isCallOpcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_CALL);
        } else if (XCapstone::isCondJumpOpcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_COND_JMP);
        } else if (XCapstone::isRetOpcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_RET);
        } else if (XCapstone::isPushOpcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_PUSH);
        } else if (XCapstone::isPopOpcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_POP);
        } else if (XCapstone::isNopOpcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_NOP);
        } else if (XCapstone::isJumpOpcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_JMP);
        } else if (XCapstone::isInt3Opcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_INT3);
        } else if (XCapstone::isSyscallOpcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_SYSCALL);
        }
    } else if ((g_dmFamily == XBinary::DMFAMILY_ARM) || (g_dmFamily == XBinary::DMFAMILY_ARM64)) {
        // TODO
    }

    return result;
}

XDisasmView::COLOR_RECORD XDisasmView::getOperandColor(const QString &sOperand)
{
    COLOR_RECORD result = {};

    bool bRef = false;
    bool bGeneralReg = false;
    bool bStackReg = false;
    bool bSegmentReg = false;
    bool bDebugReg = false;
    bool bInstructionPointerReg = false;
    bool bFlagsReg = false;
    bool bFPUReg = false;
    bool bXMMReg = false;
    bool bNumber = false;

    if (XCapstone::isRef(g_dmFamily, sOperand, g_syntax)) {
        bRef = true;
    } else if (XCapstone::isGeneralRegister(g_dmFamily, sOperand, g_syntax)) {
        bGeneralReg = true;
    } else if (XCapstone::isStackRegister(g_dmFamily, sOperand, g_syntax)) {
        bStackReg = true;
    } else if (XCapstone::isSegmentRegister(g_dmFamily, sOperand, g_syntax)) {
        bSegmentReg = true;
    } else if (XCapstone::isDebugRegister(g_dmFamily, sOperand, g_syntax)) {
        bDebugReg = true;
    } else if (XCapstone::isInstructionPointerRegister(g_dmFamily, sOperand, g_syntax)) {
        bInstructionPointerReg = true;
    } else if (XCapstone::isFlagsRegister(g_dmFamily, sOperand, g_syntax)) {
        bFlagsReg = true;
    } else if (XCapstone::isFPURegister(g_dmFamily, sOperand, g_syntax)) {
        bFPUReg = true;
    } else if (XCapstone::isXMMRegister(g_dmFamily, sOperand, g_syntax)) {
        bXMMReg = true;
    } else if (XCapstone::isNumber(g_dmFamily, sOperand, g_syntax)) {
        bNumber = true;
    }

    if (bRef) {
        result = g_mapColors.value(XOptions::ID_DISASM_COLOR_REFS);
    } else if (bNumber) {
        result = g_mapColors.value(XOptions::ID_DISASM_COLOR_NUMBERS);
    } else {
        if (g_dmFamily == XBinary::DMFAMILY_X86) {
            if (bGeneralReg || bStackReg || bSegmentReg || bDebugReg || bInstructionPointerReg || bFlagsReg || bFPUReg || bXMMReg) {
                result = g_mapColors.value(XOptions::ID_DISASM_COLOR_REGS);
                if (bGeneralReg) {
                    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_GENERAL);
                } else if (bStackReg) {
                    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_STACK);
                } else if (bSegmentReg) {
                    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_SEGMENT);
                } else if (bDebugReg) {
                    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_DEBUG);
                } else if (bInstructionPointerReg) {
                    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_IP);
                } else if (bFlagsReg) {
                    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_FLAGS);
                } else if (bFPUReg) {
                    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_FPU);
                } else if (bXMMReg) {
                    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_XMM);
                }
            }
        } else if ((g_dmFamily == XBinary::DMFAMILY_ARM) || (g_dmFamily == XBinary::DMFAMILY_ARM64)) {
            if (bGeneralReg) {
                result = g_mapColors.value(XOptions::ID_DISASM_COLOR_REGS);
                if (bGeneralReg) {
                    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_ARM_REGS_GENERAL);
                } else if (bGeneralReg) {
                    result = g_mapColors.value(XOptions::ID_DISASM_COLOR_ARM_REGS_STACK);
                }
            }
        }
    }

    return result;
}

XDisasmView::RECORD XDisasmView::_getRecordByViewPos(QList<RECORD> *pListRecord, qint64 nViewPos)
{
    RECORD result = {};

    qint32 nNumberOfRecords = pListRecord->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if (pListRecord->at(i).nViewPos == nViewPos) {
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

XDisasmView::VIEWSTRUCT XDisasmView::_getViewStructByOffset(qint64 nOffset)
{
    VIEWSTRUCT result = {};

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nOffset != -1) && (g_listViewStruct.at(i).nOffset <= nOffset) &&
            (nOffset < (g_listViewStruct.at(i).nOffset + g_listViewStruct.at(i).nSize))) {
            result = g_listViewStruct.at(i);
            break;
        }
    }

    return result;
}

XDisasmView::VIEWSTRUCT XDisasmView::_getViewStructByAddress(XADDR nAddress)
{
    VIEWSTRUCT result = {};

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nAddress != (XADDR)-1) && (g_listViewStruct.at(i).nAddress <= nAddress) &&
            (nAddress < (g_listViewStruct.at(i).nAddress + g_listViewStruct.at(i).nSize))) {
            result = g_listViewStruct.at(i);
            break;
        }
    }

    return result;
}

// XDisasmView::VIEWSTRUCT XDisasmView::_getViewStructByScroll(qint64 nValue)
// {
//     VIEWSTRUCT result = {};

//     qint32 nNumberOfRecords = g_listViewStruct.count();

//     for (qint32 i = 0; i < nNumberOfRecords; i++) {
//         if ((g_listViewStruct.at(i).nScrollStart <= nValue) && (nValue < (g_listViewStruct.at(i).nScrollStart + g_listViewStruct.at(i).nScrollCount))) {
//             result = g_listViewStruct.at(i);
//             break;
//         }
//     }

//     return result;
// }

XDisasmView::VIEWSTRUCT XDisasmView::_getViewStructByViewPos(qint64 nViewPos)
{
    VIEWSTRUCT result = {};

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nViewPos <= nViewPos) && (nViewPos < (g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize))) {
            result = g_listViewStruct.at(i);
            break;
        }
    }

    return result;
}

QList<XDisasmView::TRANSRECORD> XDisasmView::_getTransRecords(qint64 nViewPos, qint64 nSize)
{
    QList<XDisasmView::TRANSRECORD> listResult;

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        // TODO Check
        if ((((nViewPos + nSize) > g_listViewStruct.at(i).nViewPos) &&
             ((g_listViewStruct.at(i).nViewPos >= nViewPos) || ((nViewPos + nSize) < (g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize)))) ||
            (((g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize) > nViewPos) &&
             ((nViewPos >= g_listViewStruct.at(i).nViewPos) || ((g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize) < (nViewPos + nSize))))) {
            qint64 nNewViewPos = qMax(g_listViewStruct.at(i).nViewPos, nViewPos);
            qint64 nNewViewSize = qMin(g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize, nViewPos + nSize) - nNewViewPos;
            qint64 nDelta = nNewViewPos - g_listViewStruct.at(i).nViewPos;

            XDisasmView::TRANSRECORD record = {};
            record.nViewPos = nNewViewPos;
            record.nSize = nNewViewSize;
            record.nAddress = g_listViewStruct.at(i).nAddress + nDelta;
            record.nOffset = g_listViewStruct.at(i).nOffset + nDelta;

            listResult.append(record);
        }
    }

    return listResult;
}

qint64 XDisasmView::_getOffsetByViewPos(qint64 nViewPos)
{
    qint64 nResult = -1;

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nViewPos <= nViewPos) && (nViewPos < (g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize))) {
            if (g_listViewStruct.at(i).nOffset != -1) {
                nResult = g_listViewStruct.at(i).nOffset + (nViewPos - g_listViewStruct.at(i).nViewPos);
            }
            break;
        }
    }

    return nResult;
}

qint64 XDisasmView::_getViewPosByAddress(XADDR nAddress)
{
    qint64 nResult = -1;

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nAddress <= nAddress) && (nAddress < (g_listViewStruct.at(i).nAddress + g_listViewStruct.at(i).nSize))) {
            nResult = g_listViewStruct.at(i).nViewPos + (nAddress - g_listViewStruct.at(i).nAddress);
            break;
        }
    }

    return nResult;
}

XADDR XDisasmView::_getAddressByViewPos(qint64 nViewPos)
{
    XADDR nResult = -1;

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nViewPos <= nViewPos) && (nViewPos < (g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize))) {
            if (g_listViewStruct.at(i).nAddress != (XADDR)-1) {
                nResult = g_listViewStruct.at(i).nAddress + (nViewPos - g_listViewStruct.at(i).nViewPos);
            }
            break;
        }
    }

    return nResult;
}

XAbstractTableView::OS XDisasmView::cursorPositionToOS(const XAbstractTableView::CURSOR_POSITION &cursorPosition)
{
    OS osResult = {};
    osResult.nViewPos = -1;

    if ((cursorPosition.bIsValid) && (cursorPosition.ptype == PT_CELL)) {
        if (cursorPosition.nRow < g_listRecords.count()) {
            qint64 nBlockOffset = g_listRecords.at(cursorPosition.nRow).nViewPos;
            qint64 nBlockSize = 0;

            nBlockSize = g_listRecords.at(cursorPosition.nRow).disasmResult.nSize;

            osResult.nViewPos = nBlockOffset;
            osResult.nSize = nBlockSize;
        } else {
            if (!isViewPosValid(osResult.nViewPos)) {
                osResult.nViewPos = getViewSize();  // TODO Check
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

        qint64 nViewPosStart = getViewPosStart();
        qint32 nNumberLinesProPage = getLinesProPage();
        qint64 nCurrentViewPos = nViewPosStart;

        QList<XInfoDB::SHOWRECORD> listShowRecords;

//        if (isAnalyzed()) {
//            listShowRecords = getXInfoDB()->getShowRecords(nViewPosStart, nNumberLinesProPage);
//            nNumberLinesProPage = qMin(nNumberLinesProPage, listShowRecords.count());
//        }
#ifdef USE_XPROCESS
        XADDR nCurrentIP = 0;
#endif
        if (getXInfoDB()) {
#ifdef USE_XPROCESS
            nCurrentIP = getXInfoDB()->getCurrentInstructionPointerCache();
            qDebug("Current IP %s", XBinary::valueToHex(nCurrentIP).toLatin1().data());
#endif
        }

        g_listHighlightsRegion.clear();
        if (getXInfoDB()) {
            QList<XDisasmView::TRANSRECORD> listTransRecords = _getTransRecords(nViewPosStart, nNumberLinesProPage * 16);  // TODO 16 const

            qint32 nNumberOfTransRecords = listTransRecords.count();

            for (qint32 i = 0; i < nNumberOfTransRecords; i++) {
                QList<XInfoDB::BOOKMARKRECORD> listBookMarks;

                if (listTransRecords.at(i).nOffset != -1) {
                    listBookMarks = getXInfoDB()->getBookmarkRecords(listTransRecords.at(i).nOffset, XBinary::LT_OFFSET, listTransRecords.at(i).nSize);
                }

                g_listHighlightsRegion.append(_convertBookmarksToHighlightRegion(&listBookMarks));
            }
        }

        for (qint32 i = 0; i < nNumberLinesProPage; i++) {
            if (nCurrentViewPos < getViewSize()) {
                qint64 nViewSize = 0;

                RECORD record = {};

                record.nViewPos = nCurrentViewPos;

                qint32 nBufferSize = 0;

                QByteArray baBuffer;  // mb TODO fix buffer

                VIEWSTRUCT viewStruct = _getViewStructByViewPos(nCurrentViewPos);

                if (viewStruct.nSize) {
                    if (viewStruct.nOffset != -1) {
                        record.nDeviceOffset = viewStruct.nOffset + (nCurrentViewPos - viewStruct.nViewPos);
                    } else {
                        record.nDeviceOffset = -1;
                    }

                    if (viewStruct.nAddress != (XADDR)-1) {
                        record.nVirtualAddress = viewStruct.nAddress + (nCurrentViewPos - viewStruct.nViewPos);
                    } else {
                        record.nVirtualAddress = -1;
                    }

                    bool bSuccess = false;

                    if (getXInfoDB() && (record.nVirtualAddress != (XADDR)-1)) {
                        XInfoDB::SHOWRECORD showRecord = getXInfoDB()->getShowRecordByAddress(record.nVirtualAddress, true);

                        if (showRecord.bValid) {
                            if (record.nVirtualAddress != showRecord.nAddress) {
                                record.bIsAprox = true;
                            }

                            record.bIsAnalysed = true;
                            record.nVirtualAddress = showRecord.nAddress;
                            record.nDeviceOffset = showRecord.nOffset;
                            record.bHasRefFrom = showRecord.nRefFrom;

                            record.disasmResult.bIsValid = (showRecord.nSize != 0);
                            record.disasmResult.nAddress = showRecord.nAddress;
                            record.disasmResult.nSize = showRecord.nSize;
                            //                            record.disasmResult.sMnemonic = showRecord.sRecText1;
                            //                            record.disasmResult.sString = showRecord.sRecText2;

                            //                            if (g_bIsUppercase) {
                            //                                record.disasmResult.sMnemonic = record.disasmResult.sMnemonic.toUpper();
                            //                                record.disasmResult.sString = record.disasmResult.sString.toUpper();
                            //                            }

                            if (showRecord.nRefTo) {
                                XInfoDB::RELRECORD relRecord = getXInfoDB()->getRelRecordByAddress(record.nVirtualAddress);

                                record.disasmResult.relType = relRecord.relType;
                                record.disasmResult.nXrefToRelative = relRecord.nXrefToRelative;
                                record.disasmResult.memType = relRecord.memType;
                                record.disasmResult.nXrefToMemory = relRecord.nXrefToMemory;
                                record.disasmResult.nMemorySize = relRecord.nMemorySize;
                            }

                            record.nInfo = showRecord.nBranch;

                            if (record.nDeviceOffset != -1) {
                                nBufferSize = record.disasmResult.nSize;
                                baBuffer = read_array(record.nDeviceOffset, qMin(nBufferSize, g_nOpcodeSize));

                                if (showRecord.recordType == XInfoDB::RT_CODE) {
                                    XCapstone::DISASM_RESULT _disasmResult = XCapstone::disasm_ex(g_handle, g_options.disasmMode, g_syntax, baBuffer.data(),
                                                                                                  baBuffer.size(), record.nVirtualAddress, g_disasmOptions);
                                    record.disasmResult.sMnemonic = _disasmResult.sMnemonic;
                                    record.disasmResult.sString = _disasmResult.sString;
                                } else if (showRecord.recordType == XInfoDB::RT_INTDATATYPE) {
                                    if (showRecord.nSize == 1) {
                                        record.disasmResult.sMnemonic = "db";
                                    } else if (showRecord.nSize == 2) {
                                        record.disasmResult.sMnemonic = "dw";
                                    } else if (showRecord.nSize == 4) {
                                        record.disasmResult.sMnemonic = "dd";
                                    } else if (showRecord.nSize == 8) {
                                        record.disasmResult.sMnemonic = "dq";
                                    }

                                    if (record.disasmResult.sMnemonic != "") {
                                        record.disasmResult.sString = XBinary::getDataString(baBuffer.data(), baBuffer.size(), record.disasmResult.sMnemonic,
                                                                                             (getMemoryMap()->endian == XBinary::ENDIAN_BIG));
                                    }
                                }

                                record.sBytes = baBuffer.toHex().data();
                            } else {
                                // TODO
                            }

                            nViewSize = record.disasmResult.nSize;

                            bSuccess = true;
                        }
                    }

                    if (!bSuccess) {
                        if (record.nDeviceOffset != -1) {
                            nBufferSize = qMin(g_nOpcodeSize, qint32((getDevice()->size()) - record.nDeviceOffset));

                            if (getXInfoDB() && (record.nVirtualAddress != (XADDR)-1)) {
                                QList<XInfoDB::SHOWRECORD> listRecords = getXInfoDB()->getShowRecordsInRegion(record.nVirtualAddress, nBufferSize);

                                if (listRecords.count()) {
                                    nBufferSize = listRecords.at(0).nAddress - record.nVirtualAddress;
                                }
                            }
                            if ((g_options.nEntryPointAddress > record.nVirtualAddress) && (g_options.nEntryPointAddress < (record.nVirtualAddress + nBufferSize))) {
                                nBufferSize = g_options.nEntryPointAddress - record.nVirtualAddress;
                            }

                            baBuffer = read_array(record.nDeviceOffset, nBufferSize);
                            nBufferSize = baBuffer.size();

                            if (nBufferSize == 0) {
                                break;
                            }

                            record.disasmResult =
                                XCapstone::disasm_ex(g_handle, g_options.disasmMode, g_syntax, baBuffer.data(), baBuffer.size(), record.nVirtualAddress, g_disasmOptions);

                            nBufferSize = record.disasmResult.nSize;
                            baBuffer.resize(nBufferSize);

                            nViewSize = nBufferSize;

                            record.sBytes = baBuffer.toHex().data();
                        } else {
                            nViewSize = 1;
                            record.sBytes = "?";
                            record.disasmResult.bIsValid = true;
                            record.disasmResult.nAddress = record.nVirtualAddress;
                            record.disasmResult.nSize = 1;
                            record.disasmResult.sMnemonic = "db";
                            record.disasmResult.sString = "1 dup(?)";

                            if (g_disasmOptions.bIsUppercase) {
                                record.disasmResult.sMnemonic = record.disasmResult.sMnemonic.toUpper();
                                record.disasmResult.sString = record.disasmResult.sString.toUpper();
                            }
                        }
                        bSuccess = true;
                    }
                } else {
                    nViewSize = 0;
                }

                if (nViewSize == 0) {
                    break;
                }

                if (getXInfoDB()) {
#ifdef USE_XPROCESS
                    record.bIsCurrentIP = (record.nVirtualAddress == nCurrentIP);
                    // TODO different colors
                    record.breakpointType = getXInfoDB()->findBreakPointByRegion(record.nVirtualAddress, record.disasmResult.nSize).bpType;
#endif
                }

                if (record.nVirtualAddress != (XADDR)-1) {
                    if (getXInfoDB()) {
                        record.sLabel = getXInfoDB()->getSymbolStringByAddress(record.nVirtualAddress);
                    }
                }

                if (getlocationMode() == LOCMODE_THIS) {
                    qint64 nDelta = 0;
                    XADDR _nCurrent = 0;

                    if (g_nThisBaseVirtualAddress != (XADDR)-1) {
                        _nCurrent = record.nVirtualAddress;
                        nDelta = (qint64)_nCurrent - (qint64)g_nThisBaseVirtualAddress;
                    } else if (g_nThisBaseDeviceOffset != -1) {
                        _nCurrent = record.nDeviceOffset;
                        nDelta = (qint64)_nCurrent - (qint64)g_nThisBaseDeviceOffset;
                    }

                    record.sLocation = XBinary::thisToString(nDelta);
                } else if (getlocationMode() == LOCMODE_ADDRESS) {
                    QString sPrefix;
                    XADDR _nCurrent = record.nVirtualAddress;

                    if (_nCurrent == (XADDR)-1) {
                        sPrefix = QString("%1: ").arg(tr("Offset"));
                        _nCurrent = record.nDeviceOffset;
                    }

                    if (g_bIsLocationColon) {
                        record.sLocation = sPrefix + XBinary::valueToHexColon(mode, _nCurrent);
                    } else {
                        record.sLocation = sPrefix + XBinary::valueToHex(mode, _nCurrent);
                    }
                } else if (getlocationMode() == LOCMODE_OFFSET) {
                    QString sPrefix;
                    XADDR _nCurrent = record.nDeviceOffset;

                    if (_nCurrent == (XADDR)-1) {
                        sPrefix = QString("%1: ").arg(tr("Address"));
                        _nCurrent = record.nVirtualAddress;
                    }

                    if (g_bIsLocationColon) {
                        record.sLocation = sPrefix + XBinary::valueToHexColon(mode, _nCurrent);
                    } else {
                        record.sLocation = sPrefix + XBinary::valueToHex(mode, _nCurrent);
                    }
                } else if (getlocationMode() == LOCMODE_RELADDRESS) {
                    QString sPrefix;
                    QString sSymbol;
                    XADDR _nCurrent = 0;

                    if (record.nDeviceOffset != -1) {
                        sPrefix = XBinary::getMemoryRecordInfoByOffset(getMemoryMap(), record.nDeviceOffset);
                        _nCurrent = record.nDeviceOffset;
                    } else if (record.nVirtualAddress != (XADDR)-1) {
                        sPrefix = XBinary::getMemoryRecordInfoByAddress(getMemoryMap(), record.nVirtualAddress);
                        _nCurrent = record.nVirtualAddress;
                    }

                    if (record.nVirtualAddress != (XADDR)-1) {
                        if (getXInfoDB()) {
                            sSymbol = getXInfoDB()->getSymbolStringByAddress(record.nVirtualAddress);
                        }
                    }

                    if (g_bIsLocationColon) {
                        record.sLocation = XBinary::valueToHexColon(mode, _nCurrent);
                    } else {
                        record.sLocation = XBinary::valueToHex(mode, _nCurrent);
                    }

                    if (sPrefix != "") {
                        record.sLocation = QString("%1:%2").arg(sPrefix, record.sLocation);
                    }

                    if (sSymbol != "") {
                        record.sLocation = QString("%1.%2").arg(record.sLocation, sSymbol);
                    }
                }

                QList<HIGHLIGHTREGION> listHighLightRegions;

                if (record.nDeviceOffset != -1) {
                    listHighLightRegions = getHighlightRegion(&g_listHighlightsRegion, record.nDeviceOffset, XBinary::LT_OFFSET);
                }

                if (listHighLightRegions.count()) {
                    record.bIsBytesHighlighted = true;
                    record.colBytesBackground = listHighLightRegions.at(0).colBackground;
                    record.colBytesBackgroundSelected = listHighLightRegions.at(0).colBackgroundSelected;
                } else {
                    record.colBytesBackgroundSelected = getColor(TCLOLOR_SELECTED);
                }

                g_listRecords.append(record);

                nCurrentViewPos += nViewSize;
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

                            if ((nXrefTo >= g_listRecords.at(j).nVirtualAddress) &&
                                (nXrefTo < (g_listRecords.at(j).nVirtualAddress + g_listRecords.at(j).disasmResult.nSize))) {
                                nStart = j;
                                g_listRecords[i].nArraySize = nEnd - nStart;
                                g_listRecords[i].bIsEnd = true;

                                break;
                            }
                        }

                        g_listRecords[i].array = ARROW_UP;
                    } else if (nCurrentAddress < nXrefTo) {
                        nStart = i;

                        g_listRecords[i].nArraySize = nNumberOfRecords - nStart;

                        for (qint32 j = i; j <= nEnd; j++) {
                            nMaxLevel = qMax(g_listRecords.at(j).nMaxLevel, nMaxLevel);

                            if ((nXrefTo >= g_listRecords.at(j).nVirtualAddress) &&
                                (nXrefTo < (g_listRecords.at(j).nVirtualAddress + g_listRecords.at(j).disasmResult.nSize))) {
                                nEnd = j;
                                g_listRecords[i].nArraySize = nEnd - nStart;
                                g_listRecords[i].bIsEnd = true;

                                break;
                            }
                        }

                        g_listRecords[i].array = ARROW_DOWN;
                    }

                    g_listRecords[i].nArrayLevel = nMaxLevel + 1;

                    for (qint32 j = nStart; j <= nEnd; j++) {
                        g_listRecords[j].nMaxLevel = nMaxLevel + 1;
                    }
                }
            }
        }

        setCurrentBlock(nViewPosStart, (nCurrentViewPos - nViewPosStart));
    }
}

void XDisasmView::paintColumn(QPainter *pPainter, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{
    Q_UNUSED(nHeight)

    qint32 nArrowDelta = 0;

    if (nColumn == COLUMN_ARROWS) {
        qint32 nNumberOfRecords = g_listRecords.count();

        if (nNumberOfRecords) {
            for (qint32 i = 0; i < nNumberOfRecords; i++) {
                if ((g_listRecords.at(i).disasmResult.relType == XCapstone::RELTYPE_JMP) || (g_listRecords.at(i).disasmResult.relType == XCapstone::RELTYPE_JMP_COND) ||
                    (g_listRecords.at(i).disasmResult.relType == XCapstone::RELTYPE_JMP_UNCOND)) {
                    bool bIsSelected = isViewPosSelected(g_listRecords.at(i).nViewPos);
                    bool bIsCond = (g_listRecords.at(i).disasmResult.relType == XCapstone::RELTYPE_JMP_COND);

                    QPointF point1;
                    point1.setX(nLeft + nWidth - nArrowDelta);
                    point1.setY(nTop + ((i + 0.5) * getLineHeight()));

                    QPointF point2;
                    point2.setX((nLeft + nWidth - nArrowDelta) - getCharWidth() * (g_listRecords.at(i).nArrayLevel));
                    point2.setY(point1.y());

                    QPointF point3;

                    point3.setX(point2.x());

                    qint32 nDelta = getLineHeight() * g_listRecords.at(i).nArraySize;

                    if (!(g_listRecords.at(i).bIsEnd)) {
                        nDelta += 0.5 * getLineHeight();
                    }

                    if (g_listRecords.at(i).array == ARROW_UP) {
                        point3.setY(point1.y() - nDelta);
                    } else if (g_listRecords.at(i).array == ARROW_DOWN) {
                        point3.setY(point1.y() + nDelta);
                    }

                    drawArrowLine(pPainter, point1, point2, bIsSelected, bIsCond);

                    if (g_listRecords.at(i).bIsEnd) {
                        drawArrowLine(pPainter, point2, point3, bIsSelected, bIsCond);

                        QPointF point4;
                        point4.setX(point1.x());
                        point4.setY(point3.y());

                        drawArrowHead(pPainter, point3, point4, bIsSelected, bIsCond);
                    } else {
                        drawArrowHead(pPainter, point2, point3, bIsSelected, bIsCond);
                    }
                }
            }
        }
    } else if (nColumn == COLUMN_LABEL) {
        // TODO
    }
}

void XDisasmView::paintCell(QPainter *pPainter, qint32 nRow, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{
    qint32 nNumberOfRows = g_listRecords.count();

    //    qint64 nCursorOffset = getState().nCursorViewPos;

    if (nRow < nNumberOfRows) {
        qint64 nOffset = g_listRecords.at(nRow).nViewPos;

        bool bIsDebugger = false;
        //        bool bIsCurrentIP = false;
        //        bool bIsBreakpoint = false;

        if (getXInfoDB()) {
            if (nColumn == COLUMN_BREAKPOINT) {
#ifdef USE_XPROCESS
                bIsDebugger = getXInfoDB()->isDebugger();
                //                XADDR nAddress = g_listRecords.at(nRow).disasmResult.nAddress;
                //                XADDR nCurrentIP = getXInfoDB()->getCurrentInstructionPointerCache();

                //                bIsCurrentIP = ((nCurrentIP != -1) && (nAddress == nCurrentIP));
                //                bIsBreakpoint = getXInfoDB()->isBreakPointPresent(nAddress);
#endif
            }
        }

        TEXT_OPTION textOption = {};

        //        if (nColumn == COLUMN_BYTES) {

        //        }

        if (isViewPosSelected(nOffset)) {
            textOption.bIsSelected = true;

            if (g_listRecords.at(nRow).bIsBytesHighlighted && (nColumn == COLUMN_BYTES)) {
                textOption.colSelected = g_listRecords.at(nRow).colBytesBackgroundSelected;
            } else {
                textOption.colSelected = getColor(TCLOLOR_SELECTED);
            }
        }
#ifdef USE_XPROCESS
        if ((g_listRecords.at(nRow).bIsCurrentIP) && (nColumn == COLUMN_LOCATION)) {
            textOption.bIsCurrentIP = true;
        }

        if ((g_listRecords.at(nRow).breakpointType != XInfoDB::BPT_UNKNOWN) && (nColumn == COLUMN_LOCATION)) {
            textOption.bIsBreakpoint = true;
            textOption.colBreakpoint = getColor(TCLOLOR_BREAKPOINT);
        }
#endif
        if ((g_listRecords.at(nRow).bIsAnalysed) && (nColumn == COLUMN_OPCODE)) {
            textOption.bIsAnalysed = true;
            textOption.colAnalyzed = getColor(TCLOLOR_ANALYSED);
        }

        //        textOption.bIsCursor = (nOffset == nCursorOffset) && (nColumn == COLUMN_BYTES);

        if (nColumn == COLUMN_BREAKPOINT) {
            if (bIsDebugger) {
#ifdef USE_XPROCESS
                qint32 _nLeft = nLeft + nWidth - getCharWidth() - getSideDelta();
                qint32 _nWidth = getCharWidth();
                qint32 _nHeight = _nWidth;
                qint32 _nTop = nTop + 2;

                pPainter->save();

                if (g_listRecords.at(nRow).breakpointType != XInfoDB::BPT_UNKNOWN) {
                    // TODO
                    pPainter->setBrush(Qt::red);
                    pPainter->setPen(Qt::red);
                } else if (g_listRecords.at(nRow).bIsCurrentIP) {
                    pPainter->setBrush(Qt::green);  // TODO consts
                    pPainter->setPen(Qt::green);
                } else {
                    pPainter->setBrush(Qt::gray);  // TODO consts
                    pPainter->setPen(Qt::gray);
                }

                pPainter->drawEllipse(QRect(_nLeft, _nTop, _nWidth, _nHeight));
                pPainter->restore();
#endif
            }
            // TODO
        } else if (nColumn == COLUMN_LOCATION) {
            drawText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).sLocation, &textOption);
        } else if (nColumn == COLUMN_LABEL) {
            //            QString sInfoText;
            //            if (g_listRecords.at(nRow).nInfo) {
            //                sInfoText = QString::number(g_listRecords.at(nRow).nInfo);
            //            }
            drawText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).sLabel, &textOption);
        } else if (nColumn == COLUMN_BYTES) {
            if (g_listRecords.at(nRow).bIsBytesHighlighted) {
                pPainter->fillRect(nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).colBytesBackground);
            }

            drawText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).sBytes, &textOption);
        } else if (nColumn == COLUMN_OPCODE) {
            QString sOpcode = QString("%1|%2").arg(g_listRecords.at(nRow).disasmResult.sMnemonic, convertOpcodeString(g_listRecords.at(nRow).disasmResult));

            textOption.bASMHighlight = true;
            drawText(pPainter, nLeft, nTop, nWidth, nHeight, sOpcode, &textOption);
        } else if (nColumn == COLUMN_COMMENT) {
            drawText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).sComment, &textOption);
        }
    }
}

void XDisasmView::contextMenu(const QPoint &pos)
{
    if (isContextMenuEnable()) {
        MENU_STATE mstate = getMenuState();
        STATE state = getState();
        XDisasmView::RECORD record = _getRecordByViewPos(&g_listRecords, state.nSelectionViewPos);

        QMenu contextMenu(this);

        QMenu menuAnalyze(tr("Analyze"), this);
        QMenu menuHex(tr("Hex"), this);
        QMenu menuSelect(tr("Select"), this);

        QMenu menuFollowIn(tr("Follow in"), this);
        QMenu menuEdit(tr("Edit"), this);
#ifdef QT_SQL_LIB
        QMenu menuBookmarks(tr("Bookmarks"), this);
#endif

        QAction actionSelectAll(tr("Select all"), this);

        QAction actionHex(tr("Hex"), this);
        QAction actionEditHex(tr("Hex"), this);
        QAction actionReferences(this);
        QAction actionAnalyzeAll(tr("All"), this);
        QAction actionAnalyzeAnalyze(tr("Analyze"), this);
        QAction actionAnalyzeDisasm(tr("Disasm"), this);
        QAction actionAnalyzeRemove(tr("Remove"), this);
        QAction actionAnalyzeSymbols(tr("Symbols"), this);
        QAction actionAnalyzeFunctions(tr("Functions"), this);
        QAction actionAnalyzeClear(tr("Clear"), this);
#ifdef QT_SQL_LIB
        QAction actionBookmarkNew(tr("New"), this);
        QAction actionBookmarkList(tr("List"), this);
#endif
        QMenu menuGoTo(this);
        QAction actionGoToAddress(this);
        QAction actionGoToOffset(this);
        QAction actionGoToEntryPoint(this);
        QAction actionGoXrefRelative(this);
        QAction actionGoXrefMemory(this);
        {
            getShortcuts()->adjustMenu(&contextMenu, &menuGoTo, XShortcuts::GROUPID_GOTO);
            getShortcuts()->adjustAction(&menuGoTo, &actionGoToAddress, X_ID_DISASM_GOTO_ADDRESS, this, SLOT(_goToAddressSlot()));
            getShortcuts()->adjustAction(&menuGoTo, &actionGoToOffset, X_ID_DISASM_GOTO_OFFSET, this, SLOT(_goToOffsetSlot()));
            getShortcuts()->adjustAction(&menuGoTo, &actionGoToEntryPoint, X_ID_DISASM_GOTO_ENTRYPOINT, this, SLOT(_goToEntryPointSlot()),
                                         QString("0x%1").arg(g_options.nEntryPointAddress, 0, 16));

            if (record.disasmResult.relType || record.disasmResult.memType) {
                menuGoTo.addSeparator();

                if (record.disasmResult.relType) {
                    XOptions::adjustAction(&menuGoTo, &actionGoXrefRelative, QString("0x%1").arg(record.disasmResult.nXrefToRelative, 0, 16), this, SLOT(_goToXrefSlot()),
                                           XOptions::ICONTYPE_GOTO);
                    actionGoXrefRelative.setProperty("ADDRESS", record.disasmResult.nXrefToRelative);
                }

                if (record.disasmResult.memType) {
                    XOptions::adjustAction(&menuGoTo, &actionGoXrefMemory, QString("0x%1").arg(record.disasmResult.nXrefToMemory, 0, 16), this, SLOT(_goToXrefSlot()),
                                           XOptions::ICONTYPE_GOTO);
                    actionGoXrefMemory.setProperty("ADDRESS", record.disasmResult.nXrefToMemory);
                }
            }

            if (record.bHasRefFrom) {
                getShortcuts()->adjustAction(&menuGoTo, &actionReferences, X_ID_DISASM_GOTO_REFERENCES, this, SLOT(_referencesSlot()));
                actionReferences.setProperty("ADDRESS", record.disasmResult.nAddress);
            }
        }
        QMenu menuCopy(this);
        QAction actionCopyAsData(this);
        QAction actionCopyCursorOffset(this);
        QAction actionCopyCursorAddress(this);
        QAction actionCopyLocation(this);
        QAction actionCopyBytes(this);
        QAction actionCopyOpcode(this);
        QAction actionCopyComment(this);
        {
            getShortcuts()->adjustMenu(&contextMenu, &menuCopy, XShortcuts::GROUPID_COPY);
            getShortcuts()->adjustAction(&menuCopy, &actionCopyCursorAddress, X_ID_DISASM_COPY_ADDRESS, this, SLOT(_copyAddressSlot()));
            getShortcuts()->adjustAction(&menuCopy, &actionCopyCursorOffset, X_ID_DISASM_COPY_OFFSET, this, SLOT(_copyOffsetSlot()));

            if (mstate.bPhysicalSize) {
                getShortcuts()->adjustAction(&menuCopy, &actionCopyAsData, X_ID_DISASM_COPY_DATA, this, SLOT(_copyDataSlot()));
            }

            if ((record.sLocation != "") || (record.sBytes != "") || (record.disasmResult.sMnemonic != "") || (record.sComment != "")) {
                menuCopy.addSeparator();

                if (record.sLocation != "") {
                    XOptions::adjustAction(&menuCopy, &actionCopyLocation, record.sLocation, getShortcuts(), SLOT(copyRecord()), XOptions::ICONTYPE_COPY);
                    actionCopyLocation.setProperty("VALUE", record.sLocation);
                }

                if (record.sBytes != "") {
                    XOptions::adjustAction(&menuCopy, &actionCopyBytes, record.sBytes, getShortcuts(), SLOT(copyRecord()), XOptions::ICONTYPE_COPY);
                    actionCopyBytes.setProperty("VALUE", record.sBytes);
                }

                if (record.disasmResult.sMnemonic != "") {
                    QString sString = record.disasmResult.sMnemonic;

                    if (record.disasmResult.sString != "") {
                        sString.append(QString(" %1").arg(convertOpcodeString(record.disasmResult)));
                    }

                    XOptions::adjustAction(&menuCopy, &actionCopyOpcode, sString, getShortcuts(), SLOT(copyRecord()), XOptions::ICONTYPE_COPY);
                    actionCopyOpcode.setProperty("VALUE", sString);
                }

                if (record.sComment != "") {
                    XOptions::adjustAction(&menuCopy, &actionCopyComment, record.sComment, getShortcuts(), SLOT(copyRecord()), XOptions::ICONTYPE_COPY);
                    actionCopyComment.setProperty("VALUE", record.sBytes);
                }
            }
        }

        QMenu menuFind(this);
        QAction actionFindString(this);
        QAction actionFindSignature(this);
        QAction actionFindValue(this);
        QAction actionFindNext(this);

        {
            getShortcuts()->adjustMenu(&contextMenu, &menuFind, XShortcuts::GROUPID_FIND);
            getShortcuts()->adjustAction(&menuFind, &actionFindString, X_ID_DISASM_FIND_STRING, this, SLOT(_findStringSlot()));
            getShortcuts()->adjustAction(&menuFind, &actionFindSignature, X_ID_DISASM_FIND_SIGNATURE, this, SLOT(_findSignatureSlot()));
            getShortcuts()->adjustAction(&menuFind, &actionFindValue, X_ID_DISASM_FIND_VALUE, this, SLOT(_findValueSlot()));
            getShortcuts()->adjustAction(&menuFind, &actionFindNext, X_ID_DISASM_FIND_NEXT, this, SLOT(_findNextSlot()));
        }

        QAction actionDumpToFile(this);

        if (mstate.bPhysicalSize) {
            getShortcuts()->adjustAction(&contextMenu, &actionDumpToFile, X_ID_DISASM_DUMPTOFILE, this, SLOT(_dumpToFileSlot()));
        }

        QAction actionSignature(this);

        if (mstate.bPhysicalSize) {
            getShortcuts()->adjustAction(&contextMenu, &actionSignature, X_ID_DISASM_SIGNATURE, this, SLOT(_signatureSlot()));
        }

        QAction actionHexSignature(tr("Hex signature"), this);

        if (mstate.bPhysicalSize) {
            {
                actionHexSignature.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_HEX_SIGNATURE));
                connect(&actionHexSignature, SIGNAL(triggered()), this, SLOT(_hexSignatureSlot()));
                menuHex.addAction(&actionHexSignature);
            }

            contextMenu.addMenu(&menuHex);
        }

        if (mstate.bHex) {
            {
                actionHex.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FOLLOWIN_HEX));
                connect(&actionHex, SIGNAL(triggered()), this, SLOT(_hexSlot()));
                menuFollowIn.addAction(&actionHex);
            }

            contextMenu.addMenu(&menuFollowIn);
        }

        if (!(g_options.bHideReadOnly)) {
            menuEdit.setEnabled(!isReadonly());

            if (mstate.bPhysicalSize) {
                {
                    actionEditHex.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_EDIT_HEX));
                    connect(&actionEditHex, SIGNAL(triggered()), this, SLOT(_editHex()));
                    menuEdit.addAction(&actionEditHex);
                }

                contextMenu.addMenu(&menuEdit);
            }
        }
        {
            {
                actionSelectAll.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SELECT_ALL));
                connect(&actionSelectAll, SIGNAL(triggered()), this, SLOT(_selectAllSlot()));
                menuSelect.addAction(&actionSelectAll);  // TODO
            }
            contextMenu.addMenu(&menuSelect);
        }
#ifdef QT_SQL_LIB
        if ((mstate.bSize) && (getXInfoDB())) {
            {
                actionAnalyzeAll.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_ALL));
                connect(&actionAnalyzeAll, SIGNAL(triggered()), this, SLOT(_analyzeAll()));
                menuAnalyze.addAction(&actionAnalyzeAll);
            }
            {
                menuAnalyze.addSeparator();
            }
            {
                actionAnalyzeAnalyze.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_ANALYZE));
                connect(&actionAnalyzeAnalyze, SIGNAL(triggered()), this, SLOT(_analyzeAnalyze()));
                menuAnalyze.addAction(&actionAnalyzeAnalyze);
            }
            {
                actionAnalyzeDisasm.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_DISASM));
                connect(&actionAnalyzeDisasm, SIGNAL(triggered()), this, SLOT(_analyzeDisasm()));
                menuAnalyze.addAction(&actionAnalyzeDisasm);
            }
            {
                actionAnalyzeRemove.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_REMOVE));
                connect(&actionAnalyzeRemove, SIGNAL(triggered()), this, SLOT(_analyzeRemove()));
                menuAnalyze.addAction(&actionAnalyzeRemove);
            }
            {
                menuAnalyze.addSeparator();
            }
            {
                actionAnalyzeSymbols.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_SYMBOLS));
                connect(&actionAnalyzeSymbols, SIGNAL(triggered()), this, SLOT(_analyzeSymbols()));
                menuAnalyze.addAction(&actionAnalyzeSymbols);
            }
            {
                actionAnalyzeFunctions.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_FUNCTIONS));
                connect(&actionAnalyzeFunctions, SIGNAL(triggered()), this, SLOT(_analyzeFunctions()));
                menuAnalyze.addAction(&actionAnalyzeFunctions);
            }
            {
                menuAnalyze.addSeparator();
            }
            {
                actionAnalyzeClear.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_CLEAR));
                connect(&actionAnalyzeClear, SIGNAL(triggered()), this, SLOT(_analyzeClear()));
                menuAnalyze.addAction(&actionAnalyzeClear);
            }

            contextMenu.addMenu(&menuAnalyze);

            {
                actionBookmarkNew.setShortcut(getShortcuts()->getShortcut(X_ID_HEX_BOOKMARKS_NEW));
                connect(&actionBookmarkNew, SIGNAL(triggered()), this, SLOT(_bookmarkNew()));
            }
            {
                actionBookmarkList.setShortcut(getShortcuts()->getShortcut(X_ID_HEX_BOOKMARKS_LIST));
                if (getViewWidgetState(VIEWWIDGET_BOOKMARKS)) {
                    actionBookmarkList.setCheckable(true);
                    actionBookmarkList.setChecked(true);
                }
                connect(&actionBookmarkList, SIGNAL(triggered()), this, SLOT(_bookmarkList()));
            }

            menuBookmarks.addAction(&actionBookmarkNew);
            menuBookmarks.addAction(&actionBookmarkList);
            contextMenu.addMenu(&menuBookmarks);
        }
#endif

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

qint64 XDisasmView::getCurrentViewPosFromScroll()
{
    qint64 nResult = 0;

    qint32 nValue = verticalScrollBar()->value();

    qint64 nMaxValue = getMaxScrollValue();

    if (getTotalScrollCount() > (quint64)nMaxValue) {  // TODO a flag for large files
        if (nValue == getMaxScrollValue()) {
            nResult = getViewSize() - g_nBytesProLine;
        } else {
            nResult = ((double)nValue / (double)getMaxScrollValue()) * getViewSize();
        }
    } else {
        nResult = (qint64)nValue * g_nBytesProLine;
    }

    qint64 _nResult = getDisasmViewPos(nResult, getViewPosStart());  // TODO Convert

    if (_nResult != nResult) {
        nResult = _nResult;

        setCurrentViewPosToScroll(nResult);
    }

    return nResult;
}

void XDisasmView::setCurrentViewPosToScroll(qint64 nViewPos)
{
    setViewPosStart(nViewPos);  // TODO Check

    qint32 nValue = 0;

    if (getViewSize() > (getMaxScrollValue() * g_nBytesProLine)) {
        if (nViewPos == getViewSize() - g_nBytesProLine) {
            nValue = getMaxScrollValue();
        } else {
            nValue = ((double)(nViewPos) / ((double)getViewSize())) * (double)getMaxScrollValue();
        }
    } else {
        nValue = (nViewPos) / g_nBytesProLine;
    }

    verticalScrollBar()->setValue(nValue);

    //    adjust(true);  // TODO mb Remove
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
    setColumnWidth(COLUMN_LABEL, 10 * getCharWidth());
    setColumnWidth(COLUMN_OPCODE, 40 * getCharWidth());
    setColumnWidth(COLUMN_COMMENT, 60 * getCharWidth());
    setColumnWidth(COLUMN_BREAKPOINT, 2 * getCharWidth());
#ifndef USE_XPROCESS
    setColumnEnabled(COLUMN_BREAKPOINT, false);
#endif
}

void XDisasmView::registerShortcuts(bool bState)
{
    if (bState) {
        if (!g_shortCuts[SC_GOTOADDRESS])
            g_shortCuts[SC_GOTOADDRESS] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ADDRESS), this, SLOT(_goToAddressSlot()));
        if (!g_shortCuts[SC_GOTOOFFSET]) g_shortCuts[SC_GOTOOFFSET] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_OFFSET), this, SLOT(_goToOffsetSlot()));
        if (!g_shortCuts[SC_GOTOENTRYPOINT])
            g_shortCuts[SC_GOTOENTRYPOINT] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ENTRYPOINT), this, SLOT(_goToEntryPointSlot()));
        if (!g_shortCuts[SC_DUMPTOFILE]) g_shortCuts[SC_DUMPTOFILE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_DUMPTOFILE), this, SLOT(_dumpToFileSlot()));
        if (!g_shortCuts[SC_SELECTALL]) g_shortCuts[SC_SELECTALL] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SELECT_ALL), this, SLOT(_selectAllSlot()));
        if (!g_shortCuts[SC_COPYDATA]) g_shortCuts[SC_COPYDATA] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_DATA), this, SLOT(_copyDataSlot()));
        if (!g_shortCuts[SC_COPYADDRESS])
            g_shortCuts[SC_COPYADDRESS] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_ADDRESS), this, SLOT(_copyAddressSlot()));
        if (!g_shortCuts[SC_COPYOFFSET]) g_shortCuts[SC_COPYOFFSET] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_OFFSET), this, SLOT(_copyOffsetSlot()));
        if (!g_shortCuts[SC_FIND_STRING])
            g_shortCuts[SC_FIND_STRING] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_STRING), this, SLOT(_findStringSlot()));
        if (!g_shortCuts[SC_FIND_SIGNATURE])
            g_shortCuts[SC_FIND_SIGNATURE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_SIGNATURE), this, SLOT(_findSignatureSlot()));
        if (!g_shortCuts[SC_FIND_VALUE]) g_shortCuts[SC_FIND_VALUE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_VALUE), this, SLOT(_findValueSlot()));
        if (!g_shortCuts[SC_FINDNEXT]) g_shortCuts[SC_FINDNEXT] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_NEXT), this, SLOT(_findNextSlot()));
        if (!g_shortCuts[SC_SIGNATURE]) g_shortCuts[SC_SIGNATURE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SIGNATURE), this, SLOT(_signatureSlot()));
        if (!g_shortCuts[SC_HEXSIGNATURE])
            g_shortCuts[SC_HEXSIGNATURE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_HEX_SIGNATURE), this, SLOT(_hexSignatureSlot()));
        if (!g_shortCuts[SC_FOLLOWIN_HEX]) g_shortCuts[SC_FOLLOWIN_HEX] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FOLLOWIN_HEX), this, SLOT(_hexSlot()));
        if (!g_shortCuts[SC_EDIT_HEX]) g_shortCuts[SC_EDIT_HEX] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_EDIT_HEX), this, SLOT(_editHex()));
#ifdef QT_SQL_LIB
        if (getXInfoDB()) {
            if (!g_shortCuts[SC_ANALYZE_ALL])
                g_shortCuts[SC_ANALYZE_ALL] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_ALL), this, SLOT(_analyzeAll()));
            if (!g_shortCuts[SC_ANALYZE_ANALYZE])
                g_shortCuts[SC_ANALYZE_ANALYZE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_ANALYZE), this, SLOT(_analyzeAnalyze()));
            if (!g_shortCuts[SC_ANALYZE_DISASM])
                g_shortCuts[SC_ANALYZE_DISASM] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_DISASM), this, SLOT(_analyzeDisasm()));
            if (!g_shortCuts[SC_ANALYZE_REMOVE])
                g_shortCuts[SC_ANALYZE_REMOVE] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_REMOVE), this, SLOT(_analyzeRemove()));
            if (!g_shortCuts[SC_ANALYZE_SYMBOLS])
                g_shortCuts[SC_ANALYZE_SYMBOLS] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_SYMBOLS), this, SLOT(_analyzeSymbols()));
            if (!g_shortCuts[SC_ANALYZE_FUNCTIONS])
                g_shortCuts[SC_ANALYZE_FUNCTIONS] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_FUNCTIONS), this, SLOT(_analyzeFunctions()));
        }
#endif
    } else {
        for (qint32 i = 0; i < __SC_SIZE; i++) {
            if (g_shortCuts[i]) {
                delete g_shortCuts[i];
                g_shortCuts[i] = nullptr;
            }
        }
    }
}

void XDisasmView::_headerClicked(qint32 nColumn)
{
    if (nColumn == COLUMN_LOCATION) {
        if (getlocationMode() == LOCMODE_ADDRESS) {
            setColumnTitle(COLUMN_LOCATION, tr("Offset"));
            setLocationMode(LOCMODE_OFFSET);
        } else if (getlocationMode() == LOCMODE_OFFSET) {
            setColumnTitle(COLUMN_LOCATION, tr("Relative address"));
            setLocationMode(LOCMODE_RELADDRESS);
        } else if (getlocationMode() == LOCMODE_RELADDRESS) {
            setColumnTitle(COLUMN_LOCATION, tr("Address"));
            setLocationMode(LOCMODE_ADDRESS);
        } else if (getlocationMode() == LOCMODE_THIS) {
            setColumnTitle(COLUMN_LOCATION, tr("Address"));
            setLocationMode(LOCMODE_ADDRESS);
        }

        adjust(true);
    } else if (nColumn == COLUMN_OPCODE) {
        // QMenu contextMenu(this);
        // QMenu menuWidth(tr("Width"), this);

        // QAction action8(QString("8"), this);
        // action8.setProperty("width", 8);
        // connect(&action8, SIGNAL(triggered()), this, SLOT(changeWidth()));
        // menuWidth.addAction(&action8);
        // QAction action16(QString("16"), this);
        // action16.setProperty("width", 16);
        // connect(&action16, SIGNAL(triggered()), this, SLOT(changeWidth()));
        // menuWidth.addAction(&action16);
        // QAction action32(QString("32"), this);
        // action32.setProperty("width", 32);
        // connect(&action32, SIGNAL(triggered()), this, SLOT(changeWidth()));
        // menuWidth.addAction(&action32);

        // contextMenu.addMenu(&menuWidth);

        // contextMenu.exec(QCursor::pos());

        // if (g_opcodeMode == OPCODEMODE_SYMBOLADDRESS) {
        //     setColumnTitle(COLUMN_OPCODE, tr("Opcode"));
        //     g_opcodeMode = OPCODEMODE_ORIGINAL;
        // } else if (g_opcodeMode == OPCODEMODE_ORIGINAL) {
        //     setColumnTitle(COLUMN_OPCODE, QString("%1(%2)").arg(tr("Opcode"), tr("Symbol")));
        //     g_opcodeMode = OPCODEMODE_SYMBOL;
        // } else if (g_opcodeMode == OPCODEMODE_SYMBOL) {
        //     setColumnTitle(COLUMN_OPCODE, QString("%1(%2)").arg(tr("Opcode"), tr("Address")));
        //     g_opcodeMode = OPCODEMODE_ADDRESS;
        // } else if (g_opcodeMode == OPCODEMODE_ADDRESS) {
        //     setColumnTitle(COLUMN_OPCODE, QString("%1(%2->%3)").arg(tr("Opcode"), tr("Symbol"), tr("Address")));
        //     g_opcodeMode = OPCODEMODE_SYMBOLADDRESS;
        // }
        // adjust(true);
        //    } else if (nColumn == COLUMN_BYTES) {
        //        if (g_bytesMode == BYTESMODE_RAW) {
        //            setColumnTitle(COLUMN_BYTES, tr("Label"));
        //            g_bytesMode = BYTESMODE_LABEL;
        //        } else if (g_bytesMode == BYTESMODE_LABEL) {
        //            setColumnTitle(COLUMN_BYTES, tr("Bytes"));
        //            g_bytesMode = BYTESMODE_RAW;
        //        }

        //        adjust(true);
    }

    XAbstractTableView::_headerClicked(nColumn);
}

void XDisasmView::_cellDoubleClicked(qint32 nRow, qint32 nColumn)
{
    if (nColumn == COLUMN_LOCATION) {
        setColumnTitle(COLUMN_LOCATION, "");
        setLocationMode(LOCMODE_THIS);

        if (nRow < g_listRecords.count()) {
            g_nThisBaseVirtualAddress = g_listRecords.at(nRow).nViewPos;
            g_nThisBaseDeviceOffset = g_listRecords.at(nRow).nDeviceOffset;
        }

        adjust(true);
    } else if (nColumn == COLUMN_OPCODE) {
        if (nRow < g_listRecords.count()) {
            XADDR nAddress = -1;

            if (g_listRecords.at(nRow).disasmResult.relType) {
                nAddress = g_listRecords.at(nRow).disasmResult.nXrefToRelative;
            } else if (g_listRecords.at(nRow).disasmResult.memType) {
                nAddress = g_listRecords.at(nRow).disasmResult.nXrefToMemory;
            }

            if (nAddress != (XADDR)-1) {
                goToAddress(nAddress, true, true, true);
            }
        }
    }
}

qint64 XDisasmView::getFixViewPos(qint64 nViewPos)
{
    qint64 nResult = 0;

    nResult = getDisasmViewPos(nViewPos, -1);

    return nResult;
}

void XDisasmView::_goToEntryPointSlot()
{
    goToAddress(g_options.nEntryPointAddress, false, false, true);
    setFocus();
    viewport()->update();
}

void XDisasmView::_goToXrefSlot()
{
    QAction *pAction = qobject_cast<QAction *>(sender());

    if (pAction) {
        XADDR nAddress = pAction->property("ADDRESS").toULongLong();

        goToAddress(nAddress, false, false, true);
        setFocus();
        viewport()->update();
    }
}

void XDisasmView::_signatureSlot()
{
    DEVICESTATE state = getDeviceState();

    if (state.nSelectionSize) {
        DialogMultiDisasmSignature dmds(this);
        dmds.setGlobal(getShortcuts(), getGlobalOptions());
        dmds.setData(getDevice(), state.nSelectionDeviceOffset, getMemoryMap(), g_handle);

        dmds.exec();
    }
}

void XDisasmView::_hexSlot()
{
    if (g_options.bMenu_Hex) {
        DEVICESTATE state = getDeviceState();

        if (state.nSelectionDeviceOffset != (quint64)-1) {
            emit showOffsetHex(state.nSelectionDeviceOffset);
        }
    }
}

void XDisasmView::_referencesSlot()
{
    QAction *pAction = qobject_cast<QAction *>(sender());

    if (pAction) {
        XADDR nAddress = pAction->property("ADDRESS").toULongLong();

        showReferences(nAddress);
    }
}

void XDisasmView::_analyzeAll()
{
    _transfer(XInfoDBTransfer::COMMAND_ANALYZEALL);
}

void XDisasmView::_analyzeAnalyze()
{
    _transfer(XInfoDBTransfer::COMMAND_ANALYZE);
}

void XDisasmView::_analyzeDisasm()
{
    _transfer(XInfoDBTransfer::COMMAND_DISASM);
}

void XDisasmView::_analyzeRemove()
{
    _transfer(XInfoDBTransfer::COMMAND_REMOVE);
}

void XDisasmView::_analyzeClear()
{
    _transfer(XInfoDBTransfer::COMMAND_CLEAR);
}

void XDisasmView::_analyzeSymbols()
{
    if (getXInfoDB()) {
#ifdef QT_DEBUG
        qDebug("void XDisasmView::_analyzeSymbols()");
#endif
        DialogXSymbols dialogSymbols(this);
        dialogSymbols.setGlobal(getShortcuts(), getGlobalOptions());
        dialogSymbols.setData(getXInfoDB(), XSymbolsWidget::MODE_ALL, QVariant(), true);

        connect(&dialogSymbols, SIGNAL(currentSymbolChanged(XADDR, qint64)), this, SLOT(goToAddressSlot(XADDR, qint64)));

        XOptions::_adjustStayOnTop(&dialogSymbols, true);

        dialogSymbols.exec();
    }
}

void XDisasmView::_analyzeFunctions()
{
    if (getXInfoDB()) {
#ifdef QT_DEBUG
        qDebug("void XDisasmView::_analyzeFunctions()");
#endif
        DialogXSymbols dialogSymbols(this);
        dialogSymbols.setGlobal(getShortcuts(), getGlobalOptions());
        dialogSymbols.setData(getXInfoDB(), XSymbolsWidget::MODE_FUNCTIONS, QVariant(), true);

        connect(&dialogSymbols, SIGNAL(currentSymbolChanged(XADDR, qint64)), this, SLOT(goToAddressSlot(XADDR, qint64)));

        XOptions::_adjustStayOnTop(&dialogSymbols, true);

        dialogSymbols.exec();
    }
}

void XDisasmView::_transfer(XInfoDBTransfer::COMMAND command)
{
    if (getXInfoDB()) {
        STATE state = getState();

        XADDR nAddress = _getAddressByViewPos(state.nSelectionViewPos);  // TODO Offsets ???

        if (nAddress != (XADDR)-1) {
            qint64 nViewStart = getViewPosStart();

            DialogXInfoDBTransferProcess dialogTransfer(this);
            dialogTransfer.setGlobal(getShortcuts(), getGlobalOptions());
            XInfoDBTransfer::OPTIONS options = {};
            options.pDevice = getXInfoDB()->getDevice();
            options.fileType = getXInfoDB()->getFileType();
            options.nAddress = nAddress;
            options.nSize = state.nSelectionViewSize;
            options.nModuleAddress = -1;

            if (command == XInfoDBTransfer::COMMAND_DISASM) {
                options.nCount = 1;
            }

            dialogTransfer.setData(getXInfoDB(), command, options);

            dialogTransfer.showDialogDelay();
            adjustAfterAnalysis();

            setState(state);
            setViewPosStart(nViewStart);
        }
    }
}

void XDisasmView::showReferences(XADDR nAddress)
{
    if (getXInfoDB()) {
#ifdef QT_DEBUG
        qDebug("void XDisasmView::showReferences()");
#endif
        DialogXSymbols dialogSymbols(this);
        dialogSymbols.setGlobal(getShortcuts(), getGlobalOptions());
        dialogSymbols.setData(getXInfoDB(), XSymbolsWidget::MODE_REFERENCES, nAddress, true);

        connect(&dialogSymbols, SIGNAL(currentSymbolChanged(XADDR, qint64)), this, SLOT(goToAddressSlot(XADDR, qint64)));

        XOptions::_adjustStayOnTop(&dialogSymbols, true);

        dialogSymbols.exec();
    }
}
