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

    memset(g_shortCuts, 0, sizeof g_shortCuts);

    g_options = OPTIONS();
    g_disasmOptions = XCapstone::DISASM_OPTIONS();

    g_nAddressWidth = 8;
    g_nOpcodeSize = 16;  // TODO Check
    g_nThisBaseVirtualAddress = 0;
    g_nThisBaseDeviceOffset = 0;
    g_bIsAddressColon = false;
    g_bIsUppercase = false;
    g_bIsHighlight = false;
    g_syntax = XBinary::SYNTAX_DEFAULT;
    g_opcodeMode = OPCODEMODE_SYMBOLADDRESS;
    g_bytesMode = BYTESMODE_RAW;

    addColumn("");  // Arrows
                    //    addColumn(tr("Address"),0,true);
    addColumn(tr("Address"), 0, true);
    addColumn("");  // Info
    addColumn(tr("Bytes"), 0, true);
    addColumn(QString("%1(%2->%3)").arg(tr("Opcode"), tr("Symbol"), tr("Address")), 0, true);  // TODO fix it in _adjustWindow
    addColumn(tr("Comment"));

    //    setLastColumnStretch(true);

    setTextFont(getMonoFont());
    setAddressMode(LOCMODE_ADDRESS);

    _qTextOptions.setWrapMode(QTextOption::NoWrap);

    g_bHtest = true;
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
    g_dmFamily = XBinary::getDisasmFamily(g_options.disasmMode);

    g_mapColors = getColorRecordsMap();
    //    g_mapColorMapRegisters = getColorMapRegisters(g_options.disasmMode, g_syntax);
    // TODO arrows color
    // TODO BP color

    if (g_handle) {
        XCapstone::closeHandle(&g_handle);
    }

    XCapstone::openHandle(g_options.disasmMode, &g_handle, true, g_syntax);
}

void XDisasmView::adjustView()
{
    _adjustView();

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

    _adjustView();

    adjustColumns();
    adjustScrollCount();

    if (options.nInitAddress != (XADDR)-1) {
        //        qint64 nOffset = XBinary::addressToOffset(getMemoryMap(), options.nInitAddress);

        //        if (nOffset == -1) {
        //            nOffset = 0;
        //        }

        //        _goToViewOffset(nOffset, false, false, options.bAprox);
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

    //        qint64 nShowOffset = getViewOffsetStart();  // TODO convert

    //        //        XInfoDB::SHOWRECORD showRecordCursor = getXInfoDB()->getShowRecordByLine(state.nCursorViewOffset);
    //        XInfoDB::SHOWRECORD showRecordStartSelection = getXInfoDB()->getShowRecordByLine(state.nSelectionViewOffset);
    //        XInfoDB::SHOWRECORD showRecordEndSelection = getXInfoDB()->getShowRecordByLine(state.nSelectionViewOffset + state.nSelectionViewSize - 1);
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

    //        result.nSelectionLocation = viewOffsetToDeviceOffset(state.nSelectionViewOffset, bGlobalOffset);
    //        result.nSelectionSize = state.nSelectionViewSize; // TODO Check
    //        result.nShowLocation = viewOffsetToDeviceOffset(state.nSelectionViewOffset, bGlobalOffset);;

    //        return result;
    //    }

    //    return result;
    DEVICESTATE result = {};
    STATE state = getState();

    result.nSelectionDeviceOffset = viewOffsetToDeviceOffset(state.nSelectionViewOffset, bGlobalOffset);
    result.nStartDeviceOffset = viewOffsetToDeviceOffset(getViewOffsetStart(), bGlobalOffset);

    if (result.nSelectionDeviceOffset != (quint64)-1) {
        result.nSelectionSize = state.nSelectionViewSize;
        // TODO if virtual region return 0
    }

    return result;
}

void XDisasmView::setDeviceState(const DEVICESTATE &deviceState, bool bGlobalOffset)
{
    _goToViewOffset(deviceOffsetToViewOffset(deviceState.nStartDeviceOffset, bGlobalOffset));
    _initSetSelection(deviceOffsetToViewOffset(deviceState.nSelectionDeviceOffset, bGlobalOffset), deviceState.nSelectionSize);

    adjust();
    viewport()->update();
}

qint64 XDisasmView::deviceOffsetToViewOffset(qint64 nOffset, bool bGlobalOffset)
{
    qint64 nResult = 0;

    //    if (isAnalyzed()) {
    //        qint64 _nOffset = XDeviceTableView::deviceOffsetToViewOffset(nOffset, bGlobalOffset);

    //        nResult = getXInfoDB()->getShowRecordLineByOffset(_nOffset);
    //    } else {
    //        nResult = XDeviceTableView::deviceOffsetToViewOffset(nOffset, bGlobalOffset);
    //    }
    qint64 _nOffset = XDeviceTableView::deviceOffsetToViewOffset(nOffset, bGlobalOffset);

    VIEWSTRUCT viewStruct = _getViewStructByOffset(_nOffset);

    if (viewStruct.nSize) {
        nResult = viewStruct.nViewOffset + (nOffset - viewStruct.nOffset);
    }

    return nResult;
}

qint64 XDisasmView::deviceSizeToViewSize(qint64 nOffset, qint64 nSize, bool bGlobalOffset)
{
    Q_UNUSED(bGlobalOffset)

    qint64 nResult = 0;

    //    if (isAnalyzed()) {
    //        qint64 _nOffsetStart = XDeviceTableView::deviceOffsetToViewOffset(nOffset, bGlobalOffset);
    //        qint64 _nOffsetEnd = XDeviceTableView::deviceOffsetToViewOffset(nOffset + nSize, bGlobalOffset);

    //        nResult = getXInfoDB()->getShowRecordLineByOffset(_nOffsetEnd) - getXInfoDB()->getShowRecordLineByOffset(_nOffsetStart);

    //        nResult = nResult + 1;
    //    } else {
    //        nResult = XDeviceTableView::deviceOffsetToViewOffset(nOffset, nSize);
    //    }

    nResult = XDeviceTableView::deviceSizeToViewSize(nOffset, nSize);

    return nResult;
}

qint64 XDisasmView::viewOffsetToDeviceOffset(qint64 nViewOffset, bool bGlobalOffset)
{
    qint64 nResult = -1;

    VIEWSTRUCT viewStruct = _getViewStructByViewOffset(nViewOffset);

    if (viewStruct.nSize && (viewStruct.nOffset != -1)) {
        nResult = viewStruct.nOffset + (nViewOffset - viewStruct.nViewOffset);
        nResult = XDeviceTableView::viewOffsetToDeviceOffset(nResult, bGlobalOffset);
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
    qint64 nViewOffset = 0;

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        VIEWSTRUCT record = {};
        record.nAddress = getMemoryMap()->listRecords.at(i).nAddress;
        record.nOffset = getMemoryMap()->listRecords.at(i).nOffset;
        record.nSize = getMemoryMap()->listRecords.at(i).nSize;
        record.nScrollStart = nScrollStart;
        record.nViewOffset = nViewOffset;
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
            nViewOffset += record.nSize;

            g_listViewStruct.append(record);
        }
    }

    setViewSize(nViewOffset);
    setTotalScrollCount(nScrollStart);
}

qint64 XDisasmView::getViewSizeByViewOffset(qint64 nViewOffset)
{
    // TODO
    qint64 nResult = 0;

    QByteArray baData = read_array(nViewOffset, g_nOpcodeSize);

    XCapstone::DISASM_RESULT disasmResult = XCapstone::disasm_ex(g_handle, g_options.disasmMode, baData.data(), baData.size(), 0, g_disasmOptions);

    nResult = disasmResult.nSize;

    return nResult;
}

qint64 XDisasmView::addressToViewOffset(XADDR nAddress)
{
    qint64 nResult = 0;

    //    if (!isAnalyzed()) {
    //        nResult = XDeviceTableView::addressToViewOffset(nAddress);
    //    } else {
    //        nResult = getXInfoDB()->getShowRecordLineByAddress(nAddress);
    //    }
    VIEWSTRUCT viewStruct = _getViewStructByAddress(nAddress);

    if (viewStruct.nSize) {
        nResult = viewStruct.nViewOffset + (nAddress - viewStruct.nAddress);
    }

    return nResult;
}

QString XDisasmView::convertOpcodeString(const XCapstone::DISASM_RESULT &disasmResult)
{
    QString sResult = disasmResult.sString;

    if (getXInfoDB()) {
        if ((g_opcodeMode == OPCODEMODE_SYMBOLADDRESS) || (g_opcodeMode == OPCODEMODE_SYMBOL) || (g_opcodeMode == OPCODEMODE_ADDRESS)) {
            XInfoDB::RI_TYPE riType = XInfoDB::RI_TYPE_SYMBOLADDRESS;

            if (g_opcodeMode == OPCODEMODE_SYMBOLADDRESS) {
                riType = XInfoDB::RI_TYPE_SYMBOLADDRESS;
            } else if (g_opcodeMode == OPCODEMODE_SYMBOL) {
                riType = XInfoDB::RI_TYPE_SYMBOL;
            } else if (g_opcodeMode == OPCODEMODE_ADDRESS) {
                riType = XInfoDB::RI_TYPE_ADDRESS;
            }

            sResult = getXInfoDB()->convertOpcodeString(disasmResult, riType);
        }
    }

    return sResult;
}

qint64 XDisasmView::getDisasmViewOffset(qint64 nViewOffset, qint64 nOldViewOffset)
{
    qint64 nResult = nViewOffset;

    if (nViewOffset != nOldViewOffset) {
        if (nOldViewOffset == -1) {
            nOldViewOffset = nViewOffset;
        }

        bool bSuccess = false;

        VIEWSTRUCT viewStruct = _getViewStructByViewOffset(nViewOffset);
        //        VIEWSTRUCT viewStructOld = _getViewStructByViewOffset(nOldViewOffset);

        XADDR nAddress = 0;
        //        XADDR nAddressOld = 0;
        qint64 nOffset = 0;
        //        qint64 nOffsetOld = 0;

        if (viewStruct.nAddress != (XADDR)-1) {
            nAddress = viewStruct.nAddress + (nViewOffset - viewStruct.nViewOffset);
        }

        if (viewStruct.nOffset != -1) {
            nOffset = viewStruct.nOffset + (nViewOffset - viewStruct.nViewOffset);
        }

        //        if (viewStructOld.nAddress != -1) {
        //            nAddressOld = viewStructOld.nAddress + (nOldViewOffset - viewStructOld.nViewOffset);
        //        }

        //        if (viewStructOld.nOffset != -1) {
        //            nOffsetOld = viewStructOld.nOffset + (nOldViewOffset - viewStructOld.nViewOffset);
        //        }

        if (!bSuccess) {
            if (getXInfoDB()) {
                XInfoDB::SHOWRECORD showRecord = {};

                if (nAddress != (XADDR)-1) {
                    showRecord = getXInfoDB()->getShowRecordByAddress(nAddress, true);
                }
                // TODO offset !!!

                if (showRecord.bValid) {
                    if (nViewOffset > nOldViewOffset) {
                        if (nAddress != (XADDR)-1) {
                            nResult = _getViewOffsetByAddress(showRecord.nAddress + showRecord.nSize);
                        }
                    } else {
                        if (nAddress != (XADDR)-1) {
                            nResult = _getViewOffsetByAddress(showRecord.nAddress);
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
            } else if (g_dmFamily == XBinary::DMFAMILY_X86) {
                QByteArray _baData = read_array(nStartOffset, 2); // TODO optimize

                if (*((quint16 *)_baData.data()) == 0)  // 0000
                {
                    nStartOffset = S_ALIGN_DOWN(nStartOffset, 4);
                }
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
                    XCapstone::disasm_ex(g_handle, g_options.disasmMode, baData.data() + _nCurrentOffset, nSize, _nCurrentOffset, g_disasmOptions);

                if ((nOffset >= _nOffset) && (nOffset < _nOffset + disasmResult.nSize)) {
                    if (_nOffset == nOffset) {
                        _nResult = _nOffset;
                    } else {
                        if (nViewOffset > nOldViewOffset) {
                            _nResult = _nOffset + disasmResult.nSize;
                        } else {
                            _nResult = _nOffset;
                        }
                    }
                    nResult = viewStruct.nViewOffset + (_nResult - viewStruct.nOffset);

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

    QString _sMnenonic;

    if (g_bIsUppercase) {
        _sMnenonic = sMnemonic.toLower();
    } else {
        _sMnenonic = sMnemonic;
    }
    // TODO registers !!!

    if (g_bIsHighlight) {
        COLOR_RECORD opcodeColorNOP = {};

        QRect _rectMnemonic = rect;
        _rectMnemonic.setWidth(QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, sMnemonic).width());

        COLOR_RECORD opcodeColor = getOpcodeColor(_sMnenonic);

        if (XCapstone::isNopOpcode(g_dmFamily, _sMnenonic, g_syntax)) {
            opcodeColorNOP = opcodeColor;
        }

        bool bHighlight = (opcodeColor.colBackground.isValid() || opcodeColor.colMain.isValid());

        if (bHighlight) {
            pPainter->save();
        }

        if (opcodeColor.colBackground.isValid()) {
            pPainter->fillRect(_rectMnemonic, QBrush(opcodeColor.colBackground));
        }

        if (opcodeColor.colMain.isValid()) {
            pPainter->setPen(opcodeColor.colMain);
        }

        pPainter->drawText(_rectMnemonic, sMnemonic, _qTextOptions);

        if (bHighlight) {
            pPainter->restore();
        }

        if (sString != "") {
            QRect _rectString = rect;
            _rectString.setX(rect.x() + QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, sMnemonic + " ").width());

            if (opcodeColorNOP.colBackground.isValid() || opcodeColorNOP.colMain.isValid()) {
                pPainter->save();

                if (opcodeColorNOP.colBackground.isValid()) {
                    pPainter->fillRect(_rectString, QBrush(opcodeColorNOP.colBackground));
                }

                if (opcodeColorNOP.colMain.isValid()) {
                    pPainter->setPen(opcodeColorNOP.colMain);
                }

                pPainter->drawText(_rectString, sString, _qTextOptions);

                pPainter->restore();
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

void XDisasmView::drawArg(QPainter *pPainter, const QRect &rect, const QString &sText)
{
    if (sText.contains(", ")) {
        qint32 nArgCount = sText.count(", ");

        QRect _rectArg = rect;

        for (qint32 i = 0; i <= nArgCount; i++) {
            QString sArg = sText.section(", ", i, i);

            drawArg(pPainter, _rectArg, sArg);

            _rectArg.setX(_rectArg.x() + QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, sArg).width());

            if (i == (nArgCount - 1)) {
                pPainter->drawText(_rectArg, ", ", _qTextOptions);
                _rectArg.setX(_rectArg.x() + QFontMetrics(pPainter->font()).size(Qt::TextSingleLine, ", ").width());
            }
        }
    } else {
        COLOR_RECORD colorReg = getRegisterColor(sText);

        if (colorReg.colBackground.isValid() || colorReg.colMain.isValid()) {
            pPainter->save();

            if (colorReg.colBackground.isValid()) {
                pPainter->fillRect(rect, QBrush(colorReg.colBackground));
            }

            if (colorReg.colMain.isValid()) {
                pPainter->setPen(colorReg.colMain);
            }

            pPainter->drawText(rect, sText, _qTextOptions);

            pPainter->restore();
        } else {
            pPainter->drawText(rect, sText, _qTextOptions);
        }
    }
}

void XDisasmView::drawArrow(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond)
{
    pPainter->save();

    QPen pen;

    // blackPen.setWidth(10);
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

    // blackPen.setWidth(10);
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

QMap<XOptions::ID, XDisasmView::COLOR_RECORD> XDisasmView::getColorRecordsMap()
{
    QMap<XOptions::ID, COLOR_RECORD> mapResult;

    if (g_dmFamily == XBinary::DMFAMILY_X86) {
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_GENERAL, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_GENERAL));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_SEGMENT, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_SEGMENT));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_DEBUG, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_DEBUG));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_IP, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_IP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_REGS_FLAGS, getColorRecord(XOptions::ID_DISASM_COLOR_X86_REGS_FLAGS));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_CALL, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_CALL));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_JCC, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_JCC));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_RET, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_RET));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_PUSH, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_PUSH));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_POP, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_POP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_NOP, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_NOP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_JMP, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_JMP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_INT3, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_INT3));
        mapResult.insert(XOptions::ID_DISASM_COLOR_X86_OPCODE_SYSCALL, getColorRecord(XOptions::ID_DISASM_COLOR_X86_OPCODE_SYSCALL));
        // TODO
    } else if ((g_dmFamily == XBinary::DMFAMILY_ARM) || (g_dmFamily == XBinary::DMFAMILY_ARM64)) {
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_REGS, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_REGS));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_REGS_GENERAL, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_REGS_GENERAL));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_B, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_B));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_BL, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_BL));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_RET, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_RET));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_PUSH, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_PUSH));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_POP, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_POP));
        mapResult.insert(XOptions::ID_DISASM_COLOR_ARM_OPCODE_NOP, getColorRecord(XOptions::ID_DISASM_COLOR_ARM_OPCODE_NOP));
    }
    //        } else if (syntax == XBinary::SYNTAX_ATT) {
    //            {
    //                mapResult.insert("callw", colorCALL);
    //                mapResult.insert("calll", colorCALL);
    //                mapResult.insert("callq", colorCALL);
    //            }
    //            {
    //                mapResult.insert("retw", colorRET);
    //                mapResult.insert("retl", colorRET);
    //                mapResult.insert("retq", colorRET);
    //            }
    //            {
    //                mapResult.insert("pushw", colorPUSH);
    //                mapResult.insert("pushl", colorPUSH);
    //                mapResult.insert("pushq", colorPUSH);
    //            }
    //            {
    //                mapResult.insert("popw", colorPUSH);
    //                mapResult.insert("popl", colorPUSH);
    //                mapResult.insert("popq", colorPUSH);
    //            }

    //            mapResult.insert("nop", colorNOP);
    //            mapResult.insert("jmp", colorJMP);
    //            mapResult.insert("int3", colorINT3);
    //            mapResult.insert("je", colorJCC);
    //            mapResult.insert("jne", colorJCC);
    //            mapResult.insert("jz", colorJCC);
    //            mapResult.insert("jnz", colorJCC);
    //            mapResult.insert("ja", colorJCC);
    //            mapResult.insert("jc", colorJCC);
    //            mapResult.insert("syscall", colorSYSCALL);
    //        }
    //    } else if ((XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_ARM) || (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_ARM64)) {
    //        OPCODECOLOR colorBL = getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_BL);
    //        OPCODECOLOR colorRET = getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_RET);
    //        OPCODECOLOR colorPUSH = getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_PUSH);
    //        OPCODECOLOR colorPOP = getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_POP);
    //        OPCODECOLOR colorNOP = getOpcodeColor(XOptions::ID_DISASM_COLOR_ARM_NOP);

    //        mapResult.insert("bl", colorBL);
    //        mapResult.insert("ret", colorRET);
    //        mapResult.insert("push", colorPUSH);
    //        mapResult.insert("pop", colorPOP);
    //        mapResult.insert("nop", colorNOP);
    //    }

    return mapResult;
}

// QMap<QString, XDisasmView::OPCODECOLOR> XDisasmView::getColorMapRegisters(XBinary::DM disasmMode, XBinary::SYNTAX syntax)
//{
//     Q_UNUSED(syntax)

//    QMap<QString, OPCODECOLOR> mapResult;

//    if (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_X86) {
////        if (sBackgroundCode != "") {
////            result.colBackground.setNamedColor(sBackgroundCode);
////        }

//        OPCODECOLOR color = {};
//        color.colText.setNamedColor("#0000ff"); // TODO

//        mapResult.insert("rax", color);
//        mapResult.insert("eax", color);
//        mapResult.insert("ax", color);
//        mapResult.insert("al", color);
//        mapResult.insert("ah", color);
//    }

//    return mapResult;
//}

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

XDisasmView::COLOR_RECORD XDisasmView::getOpcodeColor(QString sOpcode)
{
    COLOR_RECORD result = {};

    if (g_dmFamily == XBinary::DMFAMILY_X86) {
        if (XCapstone::isCallOpcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_CALL);
        } else if (XCapstone::isJccOpcode(g_dmFamily, sOpcode, g_syntax)) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE_JCC);
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
        } else {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_OPCODE);
        }
    } else if ((g_dmFamily == XBinary::DMFAMILY_ARM) || (g_dmFamily == XBinary::DMFAMILY_ARM64)) {
        result = g_mapColors.value(XOptions::ID_DISASM_COLOR_ARM_OPCODE);
    }

    return result;
}

XDisasmView::COLOR_RECORD XDisasmView::getRegisterColor(QString sRegister)
{
    COLOR_RECORD result = {};

    bool bGeneralReg = false;
    bool bSegmentReg = false;
    bool bDebugReg = false;
    bool bInstructionPointerReg = false;
    bool bFlagsReg = false;

    if (XCapstone::isGeneralRegister(g_dmFamily, sRegister, g_syntax)) {
        bGeneralReg = true;
    } else if (XCapstone::isSegmentRegister(g_dmFamily, sRegister, g_syntax)) {
        bSegmentReg = true;
    } else if (XCapstone::isDebugRegister(g_dmFamily, sRegister, g_syntax)) {
        bDebugReg = true;
    } else if (XCapstone::isInstructionPointerRegister(g_dmFamily, sRegister, g_syntax)) {
        bInstructionPointerReg = true;
    } else if (XCapstone::isFlagsRegister(g_dmFamily, sRegister, g_syntax)) {
        bFlagsReg = true;
    }

    if (g_dmFamily == XBinary::DMFAMILY_X86) {
        if (bGeneralReg || bSegmentReg || bDebugReg) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS);
            if (bGeneralReg) {
                result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_GENERAL);
            } else if (bSegmentReg) {
                result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_SEGMENT);
            } else if (bDebugReg) {
                result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_DEBUG);
            } else if (bInstructionPointerReg) {
                result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_IP);
            } else if (bFlagsReg) {
                result = g_mapColors.value(XOptions::ID_DISASM_COLOR_X86_REGS_FLAGS);
            }  // TODO more MMX float
        }
    } else if ((g_dmFamily == XBinary::DMFAMILY_ARM) || (g_dmFamily == XBinary::DMFAMILY_ARM64)) {
        if (bGeneralReg) {
            result = g_mapColors.value(XOptions::ID_DISASM_COLOR_ARM_REGS);
            if (bGeneralReg) {
                result = g_mapColors.value(XOptions::ID_DISASM_COLOR_ARM_REGS_GENERAL);
            }
        }
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

XDisasmView::VIEWSTRUCT XDisasmView::_getViewStructByScroll(qint64 nValue)
{
    VIEWSTRUCT result = {};

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nScrollStart <= nValue) && (nValue < (g_listViewStruct.at(i).nScrollStart + g_listViewStruct.at(i).nScrollCount))) {
            result = g_listViewStruct.at(i);
            break;
        }
    }

    return result;
}

XDisasmView::VIEWSTRUCT XDisasmView::_getViewStructByViewOffset(qint64 nViewOffset)
{
    VIEWSTRUCT result = {};

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nViewOffset <= nViewOffset) && (nViewOffset < (g_listViewStruct.at(i).nViewOffset + g_listViewStruct.at(i).nSize))) {
            result = g_listViewStruct.at(i);
            break;
        }
    }

    return result;
}

QList<XDisasmView::TRANSRECORD> XDisasmView::_getTransRecords(qint64 nViewOffset, qint64 nSize)
{
    QList<XDisasmView::TRANSRECORD> listResult;

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        // TODO Check
        if ((((nViewOffset + nSize) > g_listViewStruct.at(i).nViewOffset) &&
             ((g_listViewStruct.at(i).nViewOffset >= nViewOffset) || ((nViewOffset + nSize) < (g_listViewStruct.at(i).nViewOffset + g_listViewStruct.at(i).nSize)))) ||
            (((g_listViewStruct.at(i).nViewOffset + g_listViewStruct.at(i).nSize) > nViewOffset) &&
             ((nViewOffset >= g_listViewStruct.at(i).nViewOffset) || ((g_listViewStruct.at(i).nViewOffset + g_listViewStruct.at(i).nSize) < (nViewOffset + nSize))))) {
            qint64 nNewViewOffset = qMax(g_listViewStruct.at(i).nViewOffset, nViewOffset);
            qint64 nNewViewSize = qMin(g_listViewStruct.at(i).nViewOffset + g_listViewStruct.at(i).nSize, nViewOffset + nSize) - nNewViewOffset;
            qint64 nDelta = nNewViewOffset - g_listViewStruct.at(i).nViewOffset;

            XDisasmView::TRANSRECORD record = {};
            record.nViewOffset = nNewViewOffset;
            record.nSize = nNewViewSize;
            record.nAddress = g_listViewStruct.at(i).nAddress + nDelta;
            record.nOffset = g_listViewStruct.at(i).nOffset + nDelta;

            listResult.append(record);
        }
    }

    return listResult;
}

qint64 XDisasmView::_getOffsetByViewOffset(qint64 nViewOffset)
{
    qint64 nResult = -1;

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nViewOffset <= nViewOffset) && (nViewOffset < (g_listViewStruct.at(i).nViewOffset + g_listViewStruct.at(i).nSize))) {
            if (g_listViewStruct.at(i).nOffset != -1) {
                nResult = g_listViewStruct.at(i).nOffset + (nViewOffset - g_listViewStruct.at(i).nViewOffset);
            }
            break;
        }
    }

    return nResult;
}

qint64 XDisasmView::_getViewOffsetByAddress(XADDR nAddress)
{
    qint64 nResult = -1;

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nAddress <= nAddress) && (nAddress < (g_listViewStruct.at(i).nAddress + g_listViewStruct.at(i).nSize))) {
            nResult = g_listViewStruct.at(i).nViewOffset + (nAddress - g_listViewStruct.at(i).nAddress);
            break;
        }
    }

    return nResult;
}

XADDR XDisasmView::_getAddressByViewOffset(qint64 nViewOffset)
{
    XADDR nResult = -1;

    qint32 nNumberOfRecords = g_listViewStruct.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if ((g_listViewStruct.at(i).nViewOffset <= nViewOffset) && (nViewOffset < (g_listViewStruct.at(i).nViewOffset + g_listViewStruct.at(i).nSize))) {
            if (g_listViewStruct.at(i).nAddress != (XADDR)-1) {
                nResult = g_listViewStruct.at(i).nAddress + (nViewOffset - g_listViewStruct.at(i).nViewOffset);
            }
            break;
        }
    }

    return nResult;
}

XAbstractTableView::OS XDisasmView::cursorPositionToOS(XAbstractTableView::CURSOR_POSITION cursorPosition)
{
    OS osResult = {};
    osResult.nViewOffset = -1;

    if ((cursorPosition.bIsValid) && (cursorPosition.ptype == PT_CELL)) {
        if (cursorPosition.nRow < g_listRecords.count()) {
            qint64 nBlockOffset = g_listRecords.at(cursorPosition.nRow).nViewOffset;
            qint64 nBlockSize = 0;

            nBlockSize = g_listRecords.at(cursorPosition.nRow).disasmResult.nSize;

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

        qint64 nViewOffsetStart = getViewOffsetStart();
        qint32 nNumberLinesProPage = getLinesProPage();
        qint64 nCurrentViewOffset = nViewOffsetStart;

        QList<XInfoDB::SHOWRECORD> listShowRecords;

//        if (isAnalyzed()) {
//            listShowRecords = getXInfoDB()->getShowRecords(nViewOffsetStart, nNumberLinesProPage);
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
            QList<XDisasmView::TRANSRECORD> listTransRecords = _getTransRecords(nViewOffsetStart, nNumberLinesProPage * 16);  // TODO 16 const

            qint32 nNumberOfTransRecords = listTransRecords.count();

            for (qint32 i = 0; i < nNumberOfTransRecords; i++) {
                QList<XInfoDB::BOOKMARKRECORD> listBookMarks;

                if (listTransRecords.at(i).nOffset != -1) {
                    listBookMarks = getXInfoDB()->getBookmarkRecords(listTransRecords.at(i).nOffset, XInfoDB::LT_OFFSET, listTransRecords.at(i).nSize);
                }

                g_listHighlightsRegion.append(_convertBookmarksToHighlightRegion(&listBookMarks));
            }
        }

        for (qint32 i = 0; i < nNumberLinesProPage; i++) {
            if (nCurrentViewOffset < getViewSize()) {
                qint64 nViewSize = 0;

                RECORD record = {};

                record.nViewOffset = nCurrentViewOffset;

                qint32 nBufferSize = 0;

                QByteArray baBuffer;  // mb TODO fix buffer

                VIEWSTRUCT viewStruct = _getViewStructByViewOffset(nCurrentViewOffset);

                if (viewStruct.nSize) {
                    if (viewStruct.nOffset != -1) {
                        record.nDeviceOffset = viewStruct.nOffset + (nCurrentViewOffset - viewStruct.nViewOffset);
                    } else {
                        record.nDeviceOffset = -1;
                    }

                    if (viewStruct.nAddress != (XADDR)-1) {
                        record.nVirtualAddress = viewStruct.nAddress + (nCurrentViewOffset - viewStruct.nViewOffset);
                    } else {
                        record.nVirtualAddress = -1;
                    }

                    bool bSuccess = false;

                    if (getXInfoDB() && (record.nVirtualAddress != (XADDR)-1)) {
                        XInfoDB::SHOWRECORD showRecord = getXInfoDB()->getShowRecordByAddress(record.nVirtualAddress, false);

                        if (showRecord.bValid) {
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

                                // TODO !!!
                                if ((record.disasmResult.sMnemonic == "db") && (record.disasmResult.sString == "")) {
                                    record.disasmResult.sString = XBinary::getDataString(baBuffer.data(), baBuffer.size());
                                }
                            }

                            if ((showRecord.recordType == XInfoDB::RT_CODE) && (record.nDeviceOffset != -1)) {
                                XCapstone::DISASM_RESULT _disasmResult =
                                    XCapstone::disasm_ex(g_handle, g_options.disasmMode, baBuffer.data(), baBuffer.size(), record.nVirtualAddress, g_disasmOptions);
                                record.disasmResult.sMnemonic = _disasmResult.sMnemonic;
                                record.disasmResult.sString = _disasmResult.sString;
                            }

                            record.sBytes = baBuffer.toHex().data();

                            nViewSize = record.disasmResult.nSize;

                            bSuccess = true;
                        }
                    }

                    if (!bSuccess) {
                        if (record.nDeviceOffset != -1) {
                            nBufferSize = qMin(g_nOpcodeSize, qint32((getDevice()->size()) - record.nDeviceOffset));

                            baBuffer = read_array(record.nDeviceOffset, nBufferSize);
                            nBufferSize = baBuffer.size();

                            if (nBufferSize == 0) {
                                break;
                            }

                            record.disasmResult =
                                XCapstone::disasm_ex(g_handle, g_options.disasmMode, baBuffer.data(), baBuffer.size(), record.nVirtualAddress, g_disasmOptions);

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
                        }
                        bSuccess = true;
                    }

                    if (g_bIsUppercase) {
                        record.disasmResult.sMnemonic = record.disasmResult.sMnemonic.toUpper();
                        record.disasmResult.sString = record.disasmResult.sString.toUpper();
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
                    record.bIsBreakpoint =
                        getXInfoDB()->isBreakPointPresent(record.nVirtualAddress, XInfoDB::BPT_CODE_SOFTWARE_DEFAULT);  // mb TODO region Address + Size
#endif
                }

                if (record.nVirtualAddress != (XADDR)-1) {
                    if (getXInfoDB()) {
                        record.sLabel = getXInfoDB()->getSymbolStringByAddress(record.nVirtualAddress);
                    }
                }

                if (getAddressMode() == LOCMODE_THIS) {
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
                } else if (getAddressMode() == LOCMODE_ADDRESS) {
                    QString sPrefix;
                    XADDR _nCurrent = record.nVirtualAddress;

                    if (_nCurrent == (XADDR)-1) {
                        sPrefix = QString("%1: ").arg(tr("Offset"));
                        _nCurrent = record.nDeviceOffset;
                    }

                    if (g_bIsAddressColon) {
                        record.sLocation = sPrefix + XBinary::valueToHexColon(mode, _nCurrent);
                    } else {
                        record.sLocation = sPrefix + XBinary::valueToHex(mode, _nCurrent);
                    }
                } else if (getAddressMode() == LOCMODE_OFFSET) {
                    QString sPrefix;
                    XADDR _nCurrent = record.nDeviceOffset;

                    if (_nCurrent == (XADDR)-1) {
                        sPrefix = QString("%1: ").arg(tr("Address"));
                        _nCurrent = record.nVirtualAddress;
                    }

                    if (g_bIsAddressColon) {
                        record.sLocation = sPrefix + XBinary::valueToHexColon(mode, _nCurrent);
                    } else {
                        record.sLocation = sPrefix + XBinary::valueToHex(mode, _nCurrent);
                    }
                } else if (getAddressMode() == LOCMODE_RELADDRESS) {
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

                    if (g_bIsAddressColon) {
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
                } else if (getAddressMode() == LOCMODE_LABEL) {
                    record.sLocation = record.sLabel;
                }

                QList<HIGHLIGHTREGION> listHighLightRegions;

                if (record.nDeviceOffset != -1) {
                    listHighLightRegions = getHighlightRegion(&g_listHighlightsRegion, record.nDeviceOffset, XInfoDB::LT_OFFSET);
                }

                if (listHighLightRegions.count()) {
                    record.bIsBytesHighlighted = true;
                    record.colBytesBackground = listHighLightRegions.at(0).colBackground;
                    record.colBytesBackgroundSelected = listHighLightRegions.at(0).colBackgroundSelected;
                } else {
                    record.colBytesBackgroundSelected = getColor(TCLOLOR_SELECTED);
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

                            if ((nXrefTo >= g_listRecords.at(j).nVirtualAddress) &&
                                (nXrefTo < (g_listRecords.at(j).nVirtualAddress + g_listRecords.at(j).disasmResult.nSize))) {
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

                            if ((nXrefTo >= g_listRecords.at(j).nVirtualAddress) &&
                                (nXrefTo < (g_listRecords.at(j).nVirtualAddress + g_listRecords.at(j).disasmResult.nSize))) {
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

        setCurrentBlock(nViewOffsetStart, (nCurrentViewOffset - nViewOffsetStart));
    }
}

void XDisasmView::paintColumn(QPainter *pPainter, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{
    Q_UNUSED(nHeight)

    qint32 nArrowDelta = 0;

    if (getXInfoDB()) {
        if (getXInfoDB()->isDebugger()) {
            nArrowDelta = getCharWidth() + 2 * getSideDelta();
        }
    }

    if (nColumn == COLUMN_ARROWS) {
        qint32 nNumberOfRecords = g_listRecords.count();

        if (nNumberOfRecords) {
            for (qint32 i = 0; i < nNumberOfRecords; i++) {
                if ((g_listRecords.at(i).disasmResult.relType == XCapstone::RELTYPE_JMP) || (g_listRecords.at(i).disasmResult.relType == XCapstone::RELTYPE_JMP_COND) ||
                    (g_listRecords.at(i).disasmResult.relType == XCapstone::RELTYPE_JMP_UNCOND)) {
                    bool bIsSelected = isViewOffsetSelected(g_listRecords.at(i).nViewOffset);
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
    } else if (nColumn == COLUMN_INFO) {
        // TODO
    }
}

void XDisasmView::paintCell(QPainter *pPainter, qint32 nRow, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight)
{
    qint32 nNumberOfRows = g_listRecords.count();

    //    qint64 nCursorOffset = getState().nCursorViewOffset;

    if (nRow < nNumberOfRows) {
        qint64 nOffset = g_listRecords.at(nRow).nViewOffset;

        bool bIsDebugger = false;
        //        bool bIsCurrentIP = false;
        //        bool bIsBreakpoint = false;

        if (getXInfoDB()) {
            if (nColumn == COLUMN_ARROWS) {
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

        if (isViewOffsetSelected(nOffset)) {
            textOption.bIsSelected = true;

            if (g_listRecords.at(nRow).bIsBytesHighlighted && (nColumn == COLUMN_BYTES)) {
                textOption.colSelected = g_listRecords.at(nRow).colBytesBackgroundSelected;
            } else {
                textOption.colSelected = getColor(TCLOLOR_SELECTED);
            }
        }

        if ((g_listRecords.at(nRow).bIsCurrentIP) && (nColumn == COLUMN_LOCATION)) {
            textOption.bIsCurrentIP = true;
        }

        if ((g_listRecords.at(nRow).bIsBreakpoint) && (nColumn == COLUMN_LOCATION)) {
            textOption.bIsBreakpoint = true;
            textOption.colBreakpoint = getColor(TCLOLOR_BREAKPOINT);
        }

        if ((g_listRecords.at(nRow).bIsAnalysed) && (nColumn == COLUMN_OPCODE)) {
            textOption.bIsAnalysed = true;
            textOption.colAnalyzed = getColor(TCLOLOR_ANALYSED);
        }

        //        textOption.bIsCursor = (nOffset == nCursorOffset) && (nColumn == COLUMN_BYTES);

        if (nColumn == COLUMN_ARROWS) {
            if (bIsDebugger) {
                qint32 _nLeft = nLeft + nWidth - getCharWidth() - getSideDelta();
                qint32 _nWidth = getCharWidth();
                qint32 _nHeight = _nWidth;
                qint32 _nTop = nTop + 2;

                pPainter->save();

                if (g_listRecords.at(nRow).bIsBreakpoint) {
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
            }
            // TODO
        } else if (nColumn == COLUMN_LOCATION) {
            drawText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).sLocation, &textOption);
        } else if (nColumn == COLUMN_INFO) {
            QString sInfoText;
            if (g_listRecords.at(nRow).nInfo) {
                sInfoText = QString::number(g_listRecords.at(nRow).nInfo);
            }
            drawText(pPainter, nLeft, nTop, nWidth, nHeight, sInfoText, &textOption);
        } else if (nColumn == COLUMN_BYTES) {
            if (g_listRecords.at(nRow).bIsBytesHighlighted) {
                pPainter->fillRect(nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).colBytesBackground);
            }

            if (g_bytesMode == BYTESMODE_RAW) {
                drawText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).sBytes, &textOption);
            } else if (g_bytesMode == BYTESMODE_LABEL) {
                drawText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).sLabel, &textOption);
            }
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

        QMenu contextMenu(this);
        QMenu menuGoTo(tr("Go to"), this);
        QMenu menuFind(tr("Find"), this);
        QMenu menuAnalyze(tr("Analyze"), this);
        QMenu menuHex(tr("Hex"), this);
        QMenu menuSelect(tr("Select"), this);
        QMenu menuCopy(tr("Copy"), this);
        QMenu menuFollowIn(tr("Follow in"), this);
        QMenu menuEdit(tr("Edit"), this);
#ifdef QT_SQL_LIB
        QMenu menuBookmarks(tr("Bookmarks"), this);
#endif
        QAction actionGoToAddress(tr("Address"), this);
        QAction actionGoToOffset(tr("Offset"), this);
        QAction actionGoToEntryPoint("", this);
        QAction actionGoXrefRelative("", this);
        QAction actionGoXrefMemory("", this);
        QAction actionDumpToFile(tr("Dump to file"), this);
        QAction actionHexSignature(tr("Hex signature"), this);
        QAction actionSignature(tr("Signature"), this);
        QAction actionFindString(tr("String"), this);
        QAction actionFindSignature(tr("Signature"), this);
        QAction actionFindValue(tr("Value"), this);
        QAction actionFindNext(tr("Find next"), this);
        QAction actionSelectAll(tr("Select all"), this);
        QAction actionCopyAsData(tr("Data"), this);
        QAction actionCopyCursorOffset(tr("Offset"), this);
        QAction actionCopyCursorAddress(tr("Address"), this);
        QAction actionCopyLocation("", this);
        QAction actionCopyBytes("", this);
        QAction actionCopyOpcode("", this);
        QAction actionCopyComment("", this);
        QAction actionHex(tr("Hex"), this);
        QAction actionEditHex(tr("Hex"), this);
        QAction actionReferences(tr("References"), this);
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
        {
            {
                actionGoToAddress.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ADDRESS));
                connect(&actionGoToAddress, SIGNAL(triggered()), this, SLOT(_goToAddressSlot()));
                menuGoTo.addAction(&actionGoToAddress);
            }
            {
                actionGoToOffset.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_OFFSET));
                connect(&actionGoToOffset, SIGNAL(triggered()), this, SLOT(_goToOffsetSlot()));
                menuGoTo.addAction(&actionGoToOffset);
            }
            {
                QString sEntryPointText = QString("%1(%2)").arg(tr("Entry point"), QString("0x%1").arg(g_options.nEntryPointAddress, 0, 16));
                actionGoToEntryPoint.setText(sEntryPointText);
                actionGoToEntryPoint.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_ENTRYPOINT));
                connect(&actionGoToEntryPoint, SIGNAL(triggered()), this, SLOT(_goToEntryPointSlot()));
                menuGoTo.addAction(&actionGoToEntryPoint);
            }
            // TODO go to address
            XDisasmView::RECORD record = _getRecordByViewOffset(&g_listRecords, state.nSelectionViewOffset);

            if (record.disasmResult.relType || record.disasmResult.memType) {
                menuGoTo.addSeparator();

                if (record.disasmResult.relType) {
                    actionGoXrefRelative.setText(QString("0x%1").arg(record.disasmResult.nXrefToRelative, 0, 16));
                    actionGoXrefRelative.setProperty("ADDRESS", record.disasmResult.nXrefToRelative);
                    connect(&actionGoXrefRelative, SIGNAL(triggered()), this, SLOT(_goToXrefSlot()));
                    menuGoTo.addAction(&actionGoXrefRelative);
                }

                if (record.disasmResult.memType) {
                    actionGoXrefMemory.setText(QString("0x%1").arg(record.disasmResult.nXrefToMemory, 0, 16));
                    actionGoXrefMemory.setProperty("ADDRESS", record.disasmResult.nXrefToMemory);
                    connect(&actionGoXrefMemory, SIGNAL(triggered()), this, SLOT(_goToXrefSlot()));
                    menuGoTo.addAction(&actionGoXrefMemory);
                }
            }

            if (record.bHasRefFrom) {
                actionReferences.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_GOTO_REFERENCES));
                actionReferences.setProperty("ADDRESS", record.disasmResult.nAddress);
                connect(&actionReferences, SIGNAL(triggered()), this, SLOT(_referencesSlot()));
                menuGoTo.addAction(&actionReferences);
            }

            contextMenu.addMenu(&menuGoTo);
        }
        {
            {
                actionCopyCursorAddress.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_ADDRESS));
                connect(&actionCopyCursorAddress, SIGNAL(triggered()), this, SLOT(_copyAddressSlot()));
                menuCopy.addAction(&actionCopyCursorAddress);
            }
            {
                actionCopyCursorOffset.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_OFFSET));
                connect(&actionCopyCursorOffset, SIGNAL(triggered()), this, SLOT(_copyOffsetSlot()));
                menuCopy.addAction(&actionCopyCursorOffset);
            }

            if (mstate.bPhysicalSize) {
                actionCopyAsData.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_COPY_DATA));
                connect(&actionCopyAsData, SIGNAL(triggered()), this, SLOT(_copyDataSlot()));
                menuCopy.addAction(&actionCopyAsData);
            }

            RECORD _record = _getRecordByViewOffset(&g_listRecords, state.nSelectionViewOffset);

            if ((_record.sLocation != "") || (_record.sBytes != "") || (_record.disasmResult.sMnemonic != "") || (_record.sComment != "")) {
                menuCopy.addSeparator();

                if (_record.sLocation != "") {
                    actionCopyLocation.setText(_record.sLocation);
                    actionCopyLocation.setProperty("VALUE", _record.sLocation);
                    connect(&actionCopyLocation, SIGNAL(triggered()), this, SLOT(_copyValueSlot()));
                    menuCopy.addAction(&actionCopyLocation);
                }

                if (_record.sBytes != "") {
                    actionCopyBytes.setText(_record.sBytes);
                    actionCopyBytes.setProperty("VALUE", _record.sBytes);
                    connect(&actionCopyBytes, SIGNAL(triggered()), this, SLOT(_copyValueSlot()));
                    menuCopy.addAction(&actionCopyBytes);
                }

                if (_record.disasmResult.sMnemonic != "") {
                    QString sString = _record.disasmResult.sMnemonic;

                    if (_record.disasmResult.sString != "") {
                        sString.append(QString(" %1").arg(convertOpcodeString(_record.disasmResult)));
                    }

                    actionCopyOpcode.setText(sString);
                    actionCopyOpcode.setProperty("VALUE", sString);
                    connect(&actionCopyOpcode, SIGNAL(triggered()), this, SLOT(_copyValueSlot()));
                    menuCopy.addAction(&actionCopyOpcode);
                }

                if (_record.sComment != "") {
                    actionCopyComment.setText(_record.sComment);
                    actionCopyComment.setProperty("VALUE", _record.sComment);
                    connect(&actionCopyComment, SIGNAL(triggered()), this, SLOT(_copyValueSlot()));
                    menuCopy.addAction(&actionCopyComment);
                }
            }

            contextMenu.addMenu(&menuCopy);
        }
        {
            {
                actionFindString.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_STRING));
                connect(&actionFindString, SIGNAL(triggered()), this, SLOT(_findStringSlot()));
                menuFind.addAction(&actionFindString);
            }
            {
                actionFindSignature.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_SIGNATURE));
                connect(&actionFindSignature, SIGNAL(triggered()), this, SLOT(_findSignatureSlot()));
                menuFind.addAction(&actionFindSignature);
            }
            {
                actionFindValue.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_VALUE));
                connect(&actionFindValue, SIGNAL(triggered()), this, SLOT(_findValueSlot()));
                menuFind.addAction(&actionFindValue);
            }
            {
                actionFindNext.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_FIND_NEXT));
                connect(&actionFindNext, SIGNAL(triggered()), this, SLOT(_findNextSlot()));
                menuFind.addAction(&actionFindNext);
            }

            contextMenu.addMenu(&menuFind);
        }

        if (mstate.bPhysicalSize) {
            {
                actionDumpToFile.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_DUMPTOFILE));
                connect(&actionDumpToFile, SIGNAL(triggered()), this, SLOT(_dumpToFileSlot()));
                contextMenu.addAction(&actionDumpToFile);
            }
            {
                actionSignature.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_SIGNATURE));
                connect(&actionSignature, SIGNAL(triggered()), this, SLOT(_signatureSlot()));
                contextMenu.addAction(&actionSignature);
            }
        }

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

        menuEdit.setEnabled(!isReadonly());

        if (mstate.bPhysicalSize) {
            {
                actionEditHex.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_EDIT_HEX));
                connect(&actionEditHex, SIGNAL(triggered()), this, SLOT(_editHex()));
                menuEdit.addAction(&actionEditHex);
            }

            contextMenu.addMenu(&menuEdit);
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
        if (mstate.bSize) {
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

qint64 XDisasmView::getCurrentViewOffsetFromScroll()
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

    qint64 _nResult = getDisasmViewOffset(nResult, getViewOffsetStart());  // TODO Convert

    if (_nResult != nResult) {
        nResult = _nResult;

        setCurrentViewOffsetToScroll(nResult);
    }

    return nResult;
}

void XDisasmView::setCurrentViewOffsetToScroll(qint64 nViewOffset)
{
    setViewOffsetStart(nViewOffset);  // TODO Check

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
    setColumnWidth(COLUMN_INFO, 2 * getCharWidth());
    setColumnWidth(COLUMN_OPCODE, 40 * getCharWidth());
    setColumnWidth(COLUMN_COMMENT, 60 * getCharWidth());
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
        if (!g_shortCuts[SC_ANALYZE_ALL]) g_shortCuts[SC_ANALYZE_ALL] = new QShortcut(getShortcuts()->getShortcut(X_ID_DISASM_ANALYZE_ALL), this, SLOT(_analyzeAll()));
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
        if (getAddressMode() == LOCMODE_ADDRESS) {
            setColumnTitle(COLUMN_LOCATION, tr("Offset"));
            setAddressMode(LOCMODE_OFFSET);
        } else if (getAddressMode() == LOCMODE_OFFSET) {
            setColumnTitle(COLUMN_LOCATION, tr("Relative address"));
            setAddressMode(LOCMODE_RELADDRESS);
        } else if (getAddressMode() == LOCMODE_RELADDRESS) {
            setColumnTitle(COLUMN_LOCATION, tr("Label"));
            setAddressMode(LOCMODE_LABEL);
        } else if (getAddressMode() == LOCMODE_LABEL) {
            setColumnTitle(COLUMN_LOCATION, tr("Address"));
            setAddressMode(LOCMODE_ADDRESS);
        } else if (getAddressMode() == LOCMODE_THIS) {
            setColumnTitle(COLUMN_LOCATION, tr("Address"));
            setAddressMode(LOCMODE_ADDRESS);
        }

        adjust(true);
    } else if (nColumn == COLUMN_OPCODE) {
        if (g_opcodeMode == OPCODEMODE_SYMBOLADDRESS) {
            setColumnTitle(COLUMN_OPCODE, tr("Opcode"));
            g_opcodeMode = OPCODEMODE_ORIGINAL;
        } else if (g_opcodeMode == OPCODEMODE_ORIGINAL) {
            setColumnTitle(COLUMN_OPCODE, QString("%1(%2)").arg(tr("Opcode"), tr("Symbol")));
            g_opcodeMode = OPCODEMODE_SYMBOL;
        } else if (g_opcodeMode == OPCODEMODE_SYMBOL) {
            setColumnTitle(COLUMN_OPCODE, QString("%1(%2)").arg(tr("Opcode"), tr("Address")));
            g_opcodeMode = OPCODEMODE_ADDRESS;
        } else if (g_opcodeMode == OPCODEMODE_ADDRESS) {
            setColumnTitle(COLUMN_OPCODE, QString("%1(%2->%3)").arg(tr("Opcode"), tr("Symbol"), tr("Address")));
            g_opcodeMode = OPCODEMODE_SYMBOLADDRESS;
        }

        adjust(true);
    } else if (nColumn == COLUMN_BYTES) {
        if (g_bytesMode == BYTESMODE_RAW) {
            setColumnTitle(COLUMN_BYTES, tr("Label"));
            g_bytesMode = BYTESMODE_LABEL;
        } else if (g_bytesMode == BYTESMODE_LABEL) {
            setColumnTitle(COLUMN_BYTES, tr("Bytes"));
            g_bytesMode = BYTESMODE_RAW;
        }

        adjust(true);
    }

    XAbstractTableView::_headerClicked(nColumn);
}

void XDisasmView::_cellDoubleClicked(qint32 nRow, qint32 nColumn)
{
    if (nColumn == COLUMN_LOCATION) {
        setColumnTitle(COLUMN_LOCATION, "");
        setAddressMode(LOCMODE_THIS);

        if (nRow < g_listRecords.count()) {
            g_nThisBaseVirtualAddress = g_listRecords.at(nRow).nViewOffset;
            g_nThisBaseDeviceOffset = g_listRecords.at(nRow).nDeviceOffset;
        }

        adjust(true);
    }
}

qint64 XDisasmView::getFixViewOffset(qint64 nViewOffset)
{
    qint64 nResult = 0;

    nResult = getDisasmViewOffset(nViewOffset, -1);

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

        XADDR nAddress = _getAddressByViewOffset(state.nSelectionViewOffset);  // TODO Offsets ???

        if (nAddress != (XADDR)-1) {
            qint64 nViewStart = getViewOffsetStart();

            DialogXInfoDBTransferProcess dialogTransfer(this);

            XInfoDBTransfer::OPTIONS options = {};
            options.pDevice = getXInfoDB()->getDevice();
            options.fileType = getXInfoDB()->getFileType();
            options.nAddress = nAddress;
            options.nSize = state.nSelectionViewSize;

            if (command == XInfoDBTransfer::COMMAND_DISASM) {
                options.nCount = 1;
            }

            dialogTransfer.setData(getXInfoDB(), command, options);

            dialogTransfer.showDialogDelay();
            adjustAfterAnalysis();

            setState(state);
            setViewOffsetStart(nViewStart);
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
        dialogSymbols.setData(getXInfoDB(), XSymbolsWidget::MODE_REFERENCES, nAddress, true);

        connect(&dialogSymbols, SIGNAL(currentSymbolChanged(XADDR, qint64)), this, SLOT(goToAddressSlot(XADDR, qint64)));

        XOptions::_adjustStayOnTop(&dialogSymbols, true);

        dialogSymbols.exec();
    }
}
