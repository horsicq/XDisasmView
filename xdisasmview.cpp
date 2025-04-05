/* Copyright (c) 2020-2025 hors<horsicq@gmail.com>
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
    addShortcut(X_ID_DISASM_GOTO_OFFSET, this, SLOT(_goToOffsetSlot()));
    addShortcut(X_ID_DISASM_GOTO_ADDRESS, this, SLOT(_goToAddressSlot()));
    addShortcut(X_ID_DISASM_DUMPTOFILE, this, SLOT(_dumpToFileSlot()));
    addShortcut(X_ID_DISASM_SELECT_ALL, this, SLOT(_selectAllSlot()));
    addShortcut(X_ID_DISASM_COPY_DATA, this, SLOT(_copyDataSlot()));
    addShortcut(X_ID_DISASM_COPY_OFFSET, this, SLOT(_copyOffsetSlot()));
    addShortcut(X_ID_DISASM_COPY_ADDRESS, this, SLOT(_copyAddressSlot()));
    addShortcut(X_ID_DISASM_FIND_STRING, this, SLOT(_findStringSlot()));
    addShortcut(X_ID_DISASM_FIND_SIGNATURE, this, SLOT(_findSignatureSlot()));
    addShortcut(X_ID_DISASM_FIND_VALUE, this, SLOT(_findValueSlot()));
    addShortcut(X_ID_DISASM_FIND_NEXT, this, SLOT(_findNextSlot()));
    addShortcut(X_ID_DISASM_SIGNATURE, this, SLOT(_hexSignatureSlot()));
    // addShortcut(X_ID_DISASM_FOLLOWIN_HEX, this, SLOT(_mainHexSlot()));
    addShortcut(X_ID_DISASM_EDIT_HEX, this, SLOT(_editHex()));

    // TODO click on Address -> Offset
    g_nBytesProLine = 1;

    g_options = OPTIONS();
    g_disasmOptions = XDisasmAbstract::DISASM_OPTIONS();
    g_viewMethod = VIEWMETHOD_NONE;
    g_viewDisasm = VIEWDISASM_COMPACT;

    g_nAddressWidth = 8;
    g_nOpcodeSize = 16;  // TODO Check
    g_nThisBaseVirtualAddress = 0;
    g_nThisBaseDeviceOffset = 0;
    g_bIsLocationColon = false;
    g_bIsHighlight = false;
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
}

void XDisasmView::adjustView()
{
    setTextFontFromOptions(XOptions::ID_DISASM_FONT);

    g_bIsHighlight = getGlobalOptions()->getValue(XOptions::ID_DISASM_HIGHLIGHT).toBool();
    g_disasmOptions.bIsUppercase = getGlobalOptions()->getValue(XOptions::ID_DISASM_UPPERCASE).toBool();
    // XBinary::SYNTAX syntax = XBinary::stringToSyntaxId(getGlobalOptions()->getValue(XOptions::ID_DISASM_SYNTAX).toString());
    // XBinary::DM disasmMode = g_options.disasmMode;
    g_bIsLocationColon = getGlobalOptions()->getValue(XOptions::ID_DISASM_LOCATIONCOLON).toBool();

    // g_dmFamily = XBinary::getDisasmFamily(g_options.disasmMode);

    // TODO BP color

    // if (getXInfoDB()) {
    //     g_pDisasmCore = &(getXInfoDB()->getState(g_options.memoryMapRegion.fileType)->disasmCore);
    // }

    // g_pDisasmCore->setMode(disasmMode);
    getDisasmCore()->setOptions(getGlobalOptions());

    reload(true);
    viewport()->update();
}

void XDisasmView::setData(QIODevice *pDevice, const OPTIONS &options, bool bReload)
{
    g_options = options;

    g_listRecords.clear();

    setDevice(pDevice, 0, -1);  // TODO
    setMode(options.fileType, options.disasmMode, true);
    // setMemoryMap(g_options.memoryMapRegion);

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

void XDisasmView::setViewMethod(VIEWMETHOD viewMethod)
{
    g_viewMethod = viewMethod;

    if (viewMethod == VIEWMETHOD_ANALYZED) {
        if (getXInfoDB()) {
            // if (!getXInfoDB()->isAnalyzed(g_options.memoryMapRegion.fileType)) {
            //     analyzeAll();
            // }
        }
    }

    adjustAfterAnalysis();
}

void XDisasmView::setViewDisasm(VIEWDISASM viewDisasm)
{
    g_viewDisasm = viewDisasm;

    adjustColumns();
    adjust();
    viewport()->update();
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

    result.nSelectionDeviceOffset = viewPosToDeviceOffset(state.nSelectionViewPos);
    result.nStartDeviceOffset = viewPosToDeviceOffset(getViewPosStart());

    if (result.nSelectionDeviceOffset != (quint64)-1) {
        result.nSelectionSize = state.nSelectionViewSize;
        // TODO if virtual region return 0
    }

    return result;
}

void XDisasmView::setDeviceState(const DEVICESTATE &deviceState, bool bGlobalOffset)
{
    _goToViewPos(deviceOffsetToViewPos(deviceState.nStartDeviceOffset));
    _initSetSelection(deviceOffsetToViewPos(deviceState.nSelectionDeviceOffset), deviceState.nSelectionSize);

    adjust();
    viewport()->update();
}

// qint64 XDisasmView::deviceOffsetToViewPos(qint64 nOffset, bool bGlobalOffset)
// {
//     qint64 nResult = 0;

//     //    if (isAnalyzed()) {
//     //        qint64 _nOffset = XDeviceTableView::deviceOffsetToViewPos(nOffset, bGlobalOffset);

//     //        nResult = getXInfoDB()->getShowRecordLineByOffset(_nOffset);
//     //    } else {
//     //        nResult = XDeviceTableView::deviceOffsetToViewPos(nOffset, bGlobalOffset);
//     //    }
//     qint64 _nOffset = XDeviceTableView::deviceOffsetToViewPos(nOffset, bGlobalOffset);

//     VIEWSTRUCT viewStruct = _getViewStructByOffset(_nOffset);

//     if (viewStruct.nSize) {
//         nResult = viewStruct.nViewPos + (nOffset - viewStruct.nOffset);
//     }

//     return nResult;
// }

// qint64 XDisasmView::deviceSizeToViewSize(qint64 nOffset, qint64 nSize, bool bGlobalOffset)
// {
//     Q_UNUSED(bGlobalOffset)

//     qint64 nResult = 0;

//     //    if (isAnalyzed()) {
//     //        qint64 _nOffsetStart = XDeviceTableView::deviceOffsetToViewPos(nOffset, bGlobalOffset);
//     //        qint64 _nOffsetEnd = XDeviceTableView::deviceOffsetToViewPos(nOffset + nSize, bGlobalOffset);

//     //        nResult = getXInfoDB()->getShowRecordLineByOffset(_nOffsetEnd) - getXInfoDB()->getShowRecordLineByOffset(_nOffsetStart);

//     //        nResult = nResult + 1;
//     //    } else {
//     //        nResult = XDeviceTableView::deviceOffsetToViewPos(nOffset, nSize);
//     //    }

//     nResult = XDeviceTableView::deviceSizeToViewSize(nOffset, nSize);

//     return nResult;
// }

// qint64 XDisasmView::viewPosToDeviceOffset(qint64 nViewPos, bool bGlobalOffset)
// {
//     qint64 nResult = -1;

//     VIEWSTRUCT viewStruct = _getViewStructByViewPos(nViewPos);

//     if (viewStruct.nSize && (viewStruct.nOffset != -1)) {
//         nResult = viewStruct.nOffset + (nViewPos - viewStruct.nViewPos);
//         nResult = XDeviceTableView::viewPosToDeviceOffset(nResult, bGlobalOffset);
//     }

//     return nResult;
// }

void XDisasmView::adjustScrollCount()
{
    setTotalScrollCount(getViewSize());
}

qint64 XDisasmView::getViewSizeByViewPos(qint64 nViewPos)
{
    return 1;
}

QString XDisasmView::convertOpcodeString(const XDisasmAbstract::DISASM_RESULT &disasmResult)
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
        sResult = getXInfoDB()->convertOpcodeString(disasmResult, riType, g_disasmOptions);
    }

    if (sResult == "") {
        sResult = disasmResult.sOperands;
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

        VIEWSTRUCT viewStruct = _getViewStructByViewPos(nViewPos);

        if (g_viewMethod == VIEWMETHOD_NONE) {
            qint64 nOffset = -1;

            if (viewStruct.nOffset != -1) {
                nOffset = viewStruct.nOffset + (nViewPos - viewStruct.nViewPos);
            }

            if (nOffset != -1) {
                qint64 nStartOffset = 0;
                qint64 nEndOffset = 0;

                nStartOffset = nOffset - 5 * g_nOpcodeSize;
                nEndOffset = nOffset + 5 * g_nOpcodeSize;

                if (getDisasmCore()->getDisasmFamily() == XBinary::DMFAMILY_ARM)  // TODO Check
                {
                    nStartOffset = S_ALIGN_DOWN(nStartOffset, 4);
                } else if (getDisasmCore()->getDisasmFamily() == XBinary::DMFAMILY_ARM64) {
                    nStartOffset = S_ALIGN_DOWN(nStartOffset, 4);
                } else if (getDisasmCore()->getDisasmFamily() == XBinary::DMFAMILY_M68K) {
                    nStartOffset = S_ALIGN_DOWN(nStartOffset, 2);
                } else if (getDisasmCore()->getDisasmFamily() == XBinary::DMFAMILY_X86) {
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

                    XDisasmAbstract::DISASM_RESULT disasmResult = getDisasmCore()->disAsm(baData.data() + _nCurrentOffset, nSize, _nCurrentOffset, g_disasmOptions);

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
        } else if (g_viewMethod == VIEWMETHOD_ANALYZED) {
            XADDR nAddress = -1;

            if (viewStruct.nAddress != -1) {
                nAddress = viewStruct.nAddress + (nViewPos - viewStruct.nViewPos);
            }

            if (nAddress != -1) {
                if (getXInfoDB()) {
                    // XInfoDB::STATE *pState = getXInfoDB()->getState(g_options.memoryMapRegion.fileType);

                    // if (pState) {
                    //     qint32 nIndex = getXInfoDB()->_searchXRecordByAddress(pState, nAddress, true);

                    //     if (nIndex != -1) {
                    //         XInfoDB::XRECORD record = pState->listRecords.at(nIndex);

                    //         if (nViewPos > nOldViewPos) {
                    //             nResult = viewStruct.nViewPos + record.nRelOffset + record.nSize;
                    //         } else {
                    //             nResult = viewStruct.nViewPos + record.nRelOffset;
                    //         }
                    //     }
                    // }
                }
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
    QRectF rectText;

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

    // if (pTextOption->bIsBreakpoint) {
    //     pPainter->fillRect(nLeft, nTop, nWidth, nHeight, pTextOption->colBreakpoint);
    // } else if (pTextOption->bIsAnalysed) {
    //     pPainter->fillRect(nLeft, nTop, nWidth, nHeight, pTextOption->colAnalyzed);
    // } else if (pTextOption->bIsCursor) {
    //     pPainter->fillRect(nLeft, nTop, nWidth, nHeight, viewport()->palette().color(QPalette::WindowText));
    //     pPainter->setPen(viewport()->palette().color(QPalette::Base));
    // }

    pPainter->drawText(rectText, sText, _qTextOptions);

    if (bSave) {
        pPainter->restore();
    }
}

void XDisasmView::drawDisasmText(QPainter *pPainter, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight, const XDisasmAbstract::DISASM_RESULT &disasmResult,
                                 TEXT_OPTION *pTextOption)
{
    if (g_bIsHighlight) {
        if (pTextOption->bIsSelected) {
            pPainter->fillRect(nLeft, nTop, nWidth, nHeight, pTextOption->colSelected);
        }

        QRectF rectText;
        rectText.setLeft(nLeft + getCharWidth());
        rectText.setTop(nTop + getLineDelta());
        rectText.setWidth(nWidth);
        rectText.setHeight(nHeight - getLineDelta());

        getDisasmCore()->drawDisasmText(pPainter, rectText, disasmResult);
        // TODO
    } else {
        QString sText = XDisasmAbstract::getOpcodeFullString(disasmResult);
        drawText(pPainter, nLeft, nTop, nWidth, nHeight, sText, pTextOption);
    }
}

void XDisasmView::drawArrowHead(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond)
{
    pPainter->save();

    QPen pen;

    if (bIsSelected) {
        pen.setColor(getDisasmCore()->getColorRecord(XDisasmCore::OG_ARROWS_SELECTED).colMain);
    } else {
        pen.setColor(getDisasmCore()->getColorRecord(XDisasmCore::OG_ARROWS).colMain);
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
        pen.setColor(getDisasmCore()->getColorRecord(XDisasmCore::OG_ARROWS_SELECTED).colMain);
    } else {
        pen.setColor(getDisasmCore()->getColorRecord(XDisasmCore::OG_ARROWS).colMain);
    }

    if (bIsCond) {
        pen.setStyle(Qt::DotLine);
    }

    pPainter->setPen(pen);
    pPainter->drawLine(pointStart, pointEnd);

    pPainter->restore();
}

void XDisasmView::analyzeAll()
{
    _analyzeAll();
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
        if (pListRecord->at(i).disasmResult.nAddress == nVirtualAddress) {
            result = pListRecord->at(i);

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

QList<XDisasmView::TRANSRECORD> XDisasmView::_getTransRecords(qint64 nViewPos, qint64 nSize)
{
    QList<XDisasmView::TRANSRECORD> listResult;

    // qint32 nNumberOfRecords = g_listViewStruct.count();

    // for (qint32 i = 0; i < nNumberOfRecords; i++) {
    //     // TODO Check
    //     if ((((nViewPos + nSize) > g_listViewStruct.at(i).nViewPos) &&
    //          ((g_listViewStruct.at(i).nViewPos >= nViewPos) || ((nViewPos + nSize) < (g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize)))) ||
    //         (((g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize) > nViewPos) &&
    //          ((nViewPos >= g_listViewStruct.at(i).nViewPos) || ((g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize) < (nViewPos + nSize))))) {
    //         qint64 nNewViewPos = qMax(g_listViewStruct.at(i).nViewPos, nViewPos);
    //         qint64 nNewViewSize = qMin(g_listViewStruct.at(i).nViewPos + g_listViewStruct.at(i).nSize, nViewPos + nSize) - nNewViewPos;
    //         qint64 nDelta = nNewViewPos - g_listViewStruct.at(i).nViewPos;

    //         XDisasmView::TRANSRECORD record = {};
    //         record.nViewPos = nNewViewPos;
    //         record.nSize = nNewViewSize;
    //         record.nAddress = g_listViewStruct.at(i).nAddress + nDelta;
    //         record.nOffset = g_listViewStruct.at(i).nOffset + nDelta;

    //         listResult.append(record);
    //     }
    // }

    return listResult;
}

void XDisasmView::getRecords()
{
    g_listRecords.clear();

    XInfoDB::STATE *pState = 0;

    // if (getXInfoDB() && (g_viewMethod == VIEWMETHOD_ANALYZED)) {
    //     pState = getXInfoDB()->getState(g_options.memoryMapRegion.fileType);
    // }

    qint64 nViewPosStart = getViewPosStart();
    qint32 nNumberLinesProPage = getLinesProPage();
    qint64 nCurrentViewPos = nViewPosStart;

    for (qint32 i = 0; i < nNumberLinesProPage; i++) {
        if (nCurrentViewPos < getViewSize()) {
            qint64 nDataSize = 0;

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

                XADDR nVirtualAddress = 0;

                if (viewStruct.nAddress != (XADDR)-1) {
                    nVirtualAddress = viewStruct.nAddress + (nCurrentViewPos - viewStruct.nViewPos);
                } else {
                    nVirtualAddress = -1;
                }

                if (record.nDeviceOffset != -1) {
                    if (g_viewMethod == VIEWMETHOD_NONE) {
                        nBufferSize = qMin(g_nOpcodeSize, qint32((getDevice()->size()) - record.nDeviceOffset));

                        baBuffer = read_array(record.nDeviceOffset, nBufferSize);
                        nBufferSize = baBuffer.size();

                        if (nBufferSize == 0) {
                            break;
                        }

                        record.disasmResult = getDisasmCore()->disAsm(baBuffer.data(), baBuffer.size(), nVirtualAddress, g_disasmOptions);

                        nBufferSize = record.disasmResult.nSize;
                        baBuffer.resize(nBufferSize);
                        record.sBytes = baBuffer.toHex().data();

                        nDataSize = nBufferSize;
                    } else if (g_viewMethod == VIEWMETHOD_ANALYZED) {
                        if (pState) {
                            qint32 nIndex = getXInfoDB()->_searchXRecordByAddress(pState, nVirtualAddress, false);

                            if (nIndex != -1) {
                                XInfoDB::XRECORD showRecord = pState->listRecords.at(nIndex);
                                nVirtualAddress = XInfoDB::getAddress(pState, showRecord.nRegionIndex, showRecord.nRelOffset);
                                record.nDeviceOffset = XInfoDB::getOffset(pState, showRecord.nRegionIndex, showRecord.nRelOffset);

                                if ((record.nDeviceOffset != -1) && (nVirtualAddress != -1)) {
                                    if (showRecord.nFlags & XInfoDB::XRECORD_FLAG_CODE) {
                                        QByteArray baBuffer = read_array(record.nDeviceOffset, showRecord.nSize);
                                        record.disasmResult = getDisasmCore()->disAsm(baBuffer.data(), baBuffer.size(), nVirtualAddress, g_disasmOptions);
                                        record.sBytes = baBuffer.toHex().data();

                                        nDataSize = showRecord.nSize;
                                    }
                                }

                                record.sLabel = QString::number(showRecord.nBranch);
                            } else {
                                QByteArray baBuffer = read_array(record.nDeviceOffset, 1);
                                nDataSize = 1;
                                record.sBytes = baBuffer.toHex().data();
                                record.disasmResult.bIsValid = true;
                                record.disasmResult.nAddress = nVirtualAddress;
                                record.disasmResult.nSize = 1;
                                record.disasmResult.sMnemonic = "db";
                                record.disasmResult.sOperands = record.sBytes;

                                if (g_disasmOptions.bIsUppercase) {
                                    record.disasmResult.sMnemonic = record.disasmResult.sMnemonic.toUpper();
                                    record.disasmResult.sOperands = record.disasmResult.sOperands.toUpper();
                                }
                            }
                        }
                    }
                } else {
                    nDataSize = 1;
                    record.sBytes = "?";
                    record.disasmResult.bIsValid = true;
                    record.disasmResult.nAddress = nVirtualAddress;
                    record.disasmResult.nSize = 1;
                    record.disasmResult.sMnemonic = "db";
                    record.disasmResult.sOperands = "1 dup(?)";

                    if (g_disasmOptions.bIsUppercase) {
                        record.disasmResult.sMnemonic = record.disasmResult.sMnemonic.toUpper();
                        record.disasmResult.sOperands = record.disasmResult.sOperands.toUpper();
                    }
                }
            } else {
                nDataSize = 0;
            }

            if (nDataSize == 0) {
                break;
            }

            //             if (getXInfoDB()) {
            // #ifdef USE_XPROCESS
            //                 record.bIsCurrentIP = (record.nVirtualAddress == nCurrentIP);
            //                 // TODO different colors
            //                 record.breakpointType = getXInfoDB()->findBreakPointByRegion(record.nVirtualAddress, record.disasmResult.nSize).bpType;
            // #endif
            //             }

            //             if (record.nVirtualAddress != (XADDR)-1) {
            //                 if (getXInfoDB()) {
            //                     record.sLabel = getXInfoDB()->getSymbolStringByAddress(record.nVirtualAddress);
            //                 }
            //             }

            //             QList<HIGHLIGHTREGION> listHighLightRegions;

            //             if (record.nDeviceOffset != -1) {
            //                 listHighLightRegions = getHighlightRegion(&g_listHighlightsRegion, record.nDeviceOffset, XBinary::LT_OFFSET);
            //             }

            //             if (listHighLightRegions.count()) {
            //                 record.bIsBytesHighlighted = true;
            //                 record.colBytesBackground = listHighLightRegions.at(0).colBackground;
            //                 record.colBytesBackgroundSelected = listHighLightRegions.at(0).colBackgroundSelected;
            //             } else {
            //                 record.colBytesBackgroundSelected = getColor(TCLOLOR_SELECTED);
            //             }

            g_listRecords.append(record);

            nCurrentViewPos += nDataSize;
        } else {
            break;
        }
    }

    setCurrentBlock(nViewPosStart, (nCurrentViewPos - nViewPosStart));
}

void XDisasmView::updateArrows()
{
    qint32 nNumberOfRecords = g_listRecords.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if (g_listRecords.at(i).disasmResult.relType) {
            XADDR nXrefTo = g_listRecords.at(i).disasmResult.nXrefToRelative;
            XADDR nCurrentAddress = g_listRecords.at(i).disasmResult.nAddress;

            qint32 nStart = 0;
            qint32 nEnd = nNumberOfRecords - 1;
            qint32 nMaxLevel = 0;

            if (nCurrentAddress > nXrefTo) {
                nEnd = i;

                g_listRecords[i].nArraySize = nEnd;

                for (qint32 j = i; j >= nStart; j--) {
                    nMaxLevel = qMax(g_listRecords.at(j).nMaxLevel, nMaxLevel);

                    if ((nXrefTo >= g_listRecords.at(j).disasmResult.nAddress) &&
                        (nXrefTo < (g_listRecords.at(j).disasmResult.nAddress + g_listRecords.at(j).disasmResult.nSize))) {
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

                    if ((nXrefTo >= g_listRecords.at(j).disasmResult.nAddress) &&
                        (nXrefTo < (g_listRecords.at(j).disasmResult.nAddress + g_listRecords.at(j).disasmResult.nSize))) {
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

void XDisasmView::updateLocations()
{
    XBinary::MODE mode = XBinary::getWidthModeFromByteSize(g_nAddressWidth);

    qint32 nNumberOfRecords = g_listRecords.count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if (getlocationMode() == LOCMODE_THIS) {
            qint64 nDelta = 0;
            XADDR _nCurrent = 0;

            if (g_nThisBaseVirtualAddress != (XADDR)-1) {
                _nCurrent = g_listRecords.at(i).disasmResult.nAddress;
                nDelta = (qint64)_nCurrent - (qint64)g_nThisBaseVirtualAddress;
            } else if (g_nThisBaseDeviceOffset != -1) {
                _nCurrent = g_listRecords.at(i).nDeviceOffset;
                nDelta = (qint64)_nCurrent - (qint64)g_nThisBaseDeviceOffset;
            }

            g_listRecords[i].sLocation = XBinary::thisToString(nDelta);
        } else if (getlocationMode() == LOCMODE_ADDRESS) {
            QString sPrefix;
            XADDR _nCurrent = g_listRecords.at(i).disasmResult.nAddress;

            if (_nCurrent == (XADDR)-1) {
                sPrefix = QString("%1: ").arg(tr("Offset"));
                _nCurrent = g_listRecords.at(i).nDeviceOffset;
            }

            if (g_bIsLocationColon) {
                g_listRecords[i].sLocation = sPrefix + XBinary::valueToHexColon(mode, _nCurrent);
            } else {
                g_listRecords[i].sLocation = sPrefix + XBinary::valueToHex(mode, _nCurrent);
            }
        } else if (getlocationMode() == LOCMODE_OFFSET) {
            QString sPrefix;
            XADDR _nCurrent = g_listRecords.at(i).nDeviceOffset;

            if (_nCurrent == (XADDR)-1) {
                sPrefix = QString("%1: ").arg(tr("Address"));
                _nCurrent = g_listRecords.at(i).disasmResult.nAddress;
            }

            if (g_bIsLocationColon) {
                g_listRecords[i].sLocation = sPrefix + XBinary::valueToHexColon(mode, _nCurrent);
            } else {
                g_listRecords[i].sLocation = sPrefix + XBinary::valueToHex(mode, _nCurrent);
            }
        } else if (getlocationMode() == LOCMODE_RELADDRESS) {
            QString sPrefix;
            QString sSymbol;
            XADDR _nCurrent = 0;

            if (g_listRecords.at(i).nDeviceOffset != -1) {
                sPrefix = XBinary::getMemoryRecordInfoByOffset(getMemoryMap(), g_listRecords.at(i).nDeviceOffset);
                _nCurrent = g_listRecords.at(i).nDeviceOffset;
            } else if (g_listRecords.at(i).disasmResult.nAddress != (XADDR)-1) {
                sPrefix = XBinary::getMemoryRecordInfoByAddress(getMemoryMap(), g_listRecords.at(i).disasmResult.nAddress);
                _nCurrent = g_listRecords.at(i).disasmResult.nAddress;
            }

            // if (g_listRecords.at(i).nVirtualAddress != (XADDR)-1) {
            //     if (getXInfoDB()) {
            //         sSymbol = getXInfoDB()->getSymbolStringByAddress(g_listRecords.at(i).nVirtualAddress);
            //     }
            // }

            if (g_bIsLocationColon) {
                g_listRecords[i].sLocation = XBinary::valueToHexColon(mode, _nCurrent);
            } else {
                g_listRecords[i].sLocation = XBinary::valueToHex(mode, _nCurrent);
            }

            if (sPrefix != "") {
                g_listRecords[i].sLocation = QString("%1:%2").arg(sPrefix, g_listRecords.at(i).sLocation);
            }

            if (sSymbol != "") {
                g_listRecords[i].sLocation = QString("%1.%2").arg(g_listRecords.at(i).sLocation, sSymbol);
            }
        }
    }
}

XAbstractTableView::OS XDisasmView::cursorPositionToOS(const XAbstractTableView::CURSOR_POSITION &cursorPosition)
{
    OS osResult = {};
    osResult.nViewPos = -1;

    if ((cursorPosition.bIsValid) && (cursorPosition.ptype == PT_CELL)) {
        if (cursorPosition.nRow < g_listRecords.count()) {
            qint64 nBlockOffset = g_listRecords.at(cursorPosition.nRow).nViewPos;
            qint64 nBlockSize = 0;

            // if (g_viewMethod == VIEWMETHOD_NONE) {
            //     nBlockSize = g_listRecords.at(cursorPosition.nRow).disasmResult.nSize;
            // } else if (g_viewMethod == VIEWMETHOD_ANALYZED) {
            //     nBlockSize = 1;
            // }
            nBlockSize = g_listRecords.at(cursorPosition.nRow).disasmResult.nSize;
            // nBlockSize = 1;

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
    //    g_listArrows.clear();

    if (getDevice()) {
        // QList<XInfoDB::SHOWRECORD> listShowRecords;

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

        // g_listHighlightsRegion.clear(); // TODO
        // if (getXInfoDB()) {
        //     QList<XDisasmView::TRANSRECORD> listTransRecords = _getTransRecords(nViewPosStart, nNumberLinesProPage * 16);  // TODO 16 const

        //     qint32 nNumberOfTransRecords = listTransRecords.count();

        //     for (qint32 i = 0; i < nNumberOfTransRecords; i++) {
        //         QList<XInfoDB::BOOKMARKRECORD> listBookMarks;

        //         if (listTransRecords.at(i).nOffset != -1) {
        //             listBookMarks = getXInfoDB()->getBookmarkRecords(listTransRecords.at(i).nOffset, XBinary::LT_OFFSET, listTransRecords.at(i).nSize);
        //         }

        //         g_listHighlightsRegion.append(_convertBookmarksToHighlightRegion(&listBookMarks));
        //     }
        // }

        getRecords();
        updateLocations();
        updateArrows();
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
                if ((g_listRecords.at(i).disasmResult.relType == XDisasmAbstract::RELTYPE_JMP) ||
                    (g_listRecords.at(i).disasmResult.relType == XDisasmAbstract::RELTYPE_JMP_COND) ||
                    (g_listRecords.at(i).disasmResult.relType == XDisasmAbstract::RELTYPE_JMP_UNCOND)) {
                    bool bIsSelected = isViewPosSelected(g_listRecords.at(i).nViewPos);
                    bool bIsCond = (g_listRecords.at(i).disasmResult.relType == XDisasmAbstract::RELTYPE_JMP_COND);

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
            // QString sOpcode = QString("%1|%2").arg(g_listRecords.at(nRow).disasmResult.sMnemonic, convertOpcodeString(g_listRecords.at(nRow).disasmResult));
            drawDisasmText(pPainter, nLeft, nTop, nWidth, nHeight, g_listRecords.at(nRow).disasmResult, &textOption);
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

        QMenu contextMenu(this);  // TODO

        QList<XShortcuts::MENUITEM> listMenuItems;

        getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_GOTO_ADDRESS, this, SLOT(_goToAddressSlot()), XShortcuts::GROUPID_GOTO);
        getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_GOTO_OFFSET, this, SLOT(_goToOffsetSlot()), XShortcuts::GROUPID_GOTO);

        {
            XShortcuts::MENUITEM menuItem = {};

            menuItem.nShortcutId = X_ID_DISASM_GOTO_ENTRYPOINT;
            menuItem.pRecv = this;
            menuItem.pMethod = SLOT(_goToEntryPointSlot());
            menuItem.nSubgroups = XShortcuts::GROUPID_GOTO;
            menuItem.sText = QString("0x%1").arg(g_options.nEntryPointAddress, 0, 16);

            listMenuItems.append(menuItem);
        }

        if (record.disasmResult.relType || record.disasmResult.memType) {
            getShortcuts()->_addMenuSeparator(&listMenuItems, XShortcuts::GROUPID_GOTO);

            if (record.disasmResult.relType) {
                XShortcuts::MENUITEM menuItem = {};

                menuItem.pRecv = this;
                menuItem.pMethod = SLOT(_goToXrefSlot());
                menuItem.nSubgroups = XShortcuts::GROUPID_GOTO;
                menuItem.sText = QString("0x%1").arg(record.disasmResult.nXrefToRelative, 0, 16);
                menuItem.iconType = XOptions::ICONTYPE_GOTO;
                menuItem.sPropertyName = "ADDRESS";
                menuItem.varProperty = record.disasmResult.nXrefToRelative;

                listMenuItems.append(menuItem);
            }

            if (record.disasmResult.memType) {
                XShortcuts::MENUITEM menuItem = {};

                menuItem.pRecv = this;
                menuItem.pMethod = SLOT(_goToXrefSlot());
                menuItem.nSubgroups = XShortcuts::GROUPID_GOTO;
                menuItem.sText = QString("0x%1").arg(record.disasmResult.nXrefToMemory, 0, 16);
                menuItem.iconType = XOptions::ICONTYPE_GOTO;
                menuItem.sPropertyName = "ADDRESS";
                menuItem.varProperty = record.disasmResult.nXrefToMemory;

                listMenuItems.append(menuItem);
            }
        }

        if (record.bHasRefFrom) {
            XShortcuts::MENUITEM menuItem = {};

            menuItem.pRecv = this;
            menuItem.pMethod = SLOT(_referencesSlot());
            menuItem.nSubgroups = XShortcuts::GROUPID_GOTO;
            menuItem.nShortcutId = X_ID_DISASM_GOTO_REFERENCES;
            menuItem.sPropertyName = "ADDRESS";
            menuItem.varProperty = record.disasmResult.nAddress;

            listMenuItems.append(menuItem);
        }

        getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_COPY_ADDRESS, this, SLOT(_copyAddressSlot()), XShortcuts::GROUPID_COPY);
        getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_COPY_OFFSET, this, SLOT(_copyOffsetSlot()), XShortcuts::GROUPID_COPY);

        if (mstate.bPhysicalSize) {
            getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_COPY_DATA, this, SLOT(_copyDataSlot()), XShortcuts::GROUPID_COPY);
        }

        if ((record.sLocation != "") || (record.sBytes != "") || (record.disasmResult.sMnemonic != "") || (record.sComment != "")) {
            getShortcuts()->_addMenuSeparator(&listMenuItems, XShortcuts::GROUPID_COPY);

            if (record.sLocation != "") {
                XShortcuts::MENUITEM menuItem = {};

                menuItem.pRecv = getShortcuts();
                menuItem.pMethod = SLOT(copyRecord());
                menuItem.nSubgroups = XShortcuts::GROUPID_COPY;
                menuItem.sText = record.sLocation;
                menuItem.sPropertyName = "VALUE";
                menuItem.varProperty = record.sLocation;

                listMenuItems.append(menuItem);
            }

            if (record.sBytes != "") {
                XShortcuts::MENUITEM menuItem = {};

                menuItem.pRecv = getShortcuts();
                menuItem.pMethod = SLOT(copyRecord());
                menuItem.nSubgroups = XShortcuts::GROUPID_COPY;
                menuItem.sText = record.sBytes;
                menuItem.sPropertyName = "VALUE";
                menuItem.varProperty = record.sBytes;

                listMenuItems.append(menuItem);
            }

            if (record.disasmResult.sMnemonic != "") {
                QString sString = record.disasmResult.sMnemonic;

                if (record.disasmResult.sOperands != "") {
                    sString.append(QString(" %1").arg(convertOpcodeString(record.disasmResult)));
                }

                XShortcuts::MENUITEM menuItem = {};

                menuItem.pRecv = getShortcuts();
                menuItem.pMethod = SLOT(copyRecord());
                menuItem.nSubgroups = XShortcuts::GROUPID_COPY;
                menuItem.sText = sString;
                menuItem.sPropertyName = "VALUE";
                menuItem.varProperty = sString;

                listMenuItems.append(menuItem);
            }

            if (record.sComment != "") {
                XShortcuts::MENUITEM menuItem = {};

                menuItem.pRecv = getShortcuts();
                menuItem.pMethod = SLOT(copyRecord());
                menuItem.nSubgroups = XShortcuts::GROUPID_COPY;
                menuItem.sText = record.sComment;
                menuItem.sPropertyName = "VALUE";
                menuItem.varProperty = record.sComment;

                listMenuItems.append(menuItem);
            }
        }

        getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_FIND_STRING, this, SLOT(_findStringSlot()), XShortcuts::GROUPID_FIND);
        getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_FIND_SIGNATURE, this, SLOT(_findSignatureSlot()), XShortcuts::GROUPID_FIND);
        getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_FIND_VALUE, this, SLOT(_findValueSlot()), XShortcuts::GROUPID_FIND);
        getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_FIND_NEXT, this, SLOT(_findNextSlot()), XShortcuts::GROUPID_FIND);

        if (mstate.bPhysicalSize) {
            getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_DUMPTOFILE, this, SLOT(_dumpToFileSlot()), XShortcuts::GROUPID_NONE);
            getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_SIGNATURE, this, SLOT(_signatureSlot()), XShortcuts::GROUPID_NONE);
            getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_HEX_SIGNATURE, this, SLOT(_hexSignatureSlot()), XShortcuts::GROUPID_HEX);
        }

        if (mstate.bHex) {
            getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_FOLLOWIN_HEX, this, SLOT(_hexSlot()), XShortcuts::GROUPID_FOLLOWIN);
        }

        if (!isReadonly()) {
            if (mstate.bPhysicalSize) {
                getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_EDIT_HEX, this, SLOT(_editHex()), XShortcuts::GROUPID_EDIT);
            }
            getShortcuts()->_addMenuItem(&listMenuItems, X_ID_DISASM_EDIT_PATCH, this, SLOT(_editPatch()), XShortcuts::GROUPID_EDIT);
        }

        QList<QObject *> listObjects = getShortcuts()->adjustContextMenu(&contextMenu, &listMenuItems);

        contextMenu.exec(pos);

        XOptions::deleteQObjectList(&listObjects);

        return;

        QMenu menuAnalyze(tr("Analyze"), this);
        QMenu menuBookmarks(tr("Bookmarks"), this);
        QAction actionAnalyzeAll(tr("All"), this);
        QAction actionAnalyzeAnalyze(tr("Analyze"), this);
        QAction actionAnalyzeDisasm(tr("Disasm"), this);
        QAction actionAnalyzeRemove(tr("Remove"), this);
        QAction actionAnalyzeSymbols(tr("Symbols"), this);
        QAction actionAnalyzeFunctions(tr("Functions"), this);
        QAction actionAnalyzeClear(tr("Clear"), this);
        QAction actionBookmarkNew(tr("New"), this);
        QAction actionBookmarkList(tr("List"), this);

        QMenu menuEdit(this);
        QAction actionEditHex(this);

        if (!(g_options.bHideReadOnly)) {
            if (mstate.bPhysicalSize) {
                menuEdit.setEnabled(!isReadonly());
                getShortcuts()->adjustMenu(&contextMenu, &menuEdit, XShortcuts::GROUPID_EDIT);
                getShortcuts()->adjustAction(&menuEdit, &actionEditHex, X_ID_DISASM_EDIT_HEX, this, SLOT(_editHex()));
            }
        }

        QMenu menuSelect(this);
        QAction actionSelectAll(this);

        {
            getShortcuts()->adjustMenu(&contextMenu, &menuSelect, XShortcuts::GROUPID_SELECT);
            getShortcuts()->adjustAction(&menuSelect, &actionSelectAll, X_ID_DISASM_SELECT_ALL, this, SLOT(_selectAllSlot()));
        }

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
                actionBookmarkNew.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_BOOKMARKS_NEW));
                connect(&actionBookmarkNew, SIGNAL(triggered()), this, SLOT(_bookmarkNew()));
            }
            {
                actionBookmarkList.setShortcut(getShortcuts()->getShortcut(X_ID_DISASM_BOOKMARKS_LIST));
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

    qint64 _nViewPosStart = getViewPosStart();
    qint64 _nResult = getDisasmViewPos(nResult, _nViewPosStart);  // TODO Convert

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
    } else {
        g_nAddressWidth = 8;
        setColumnWidth(COLUMN_LOCATION, 2 * getCharWidth() + fm.boundingRect("0000:0000").width());
    }

    if (g_viewDisasm == VIEWDISASM_FULL) {
        QString sBytes;

        for (qint32 i = 0; i < g_nOpcodeSize; i++) {
            sBytes += "00";
        }

        setColumnWidth(COLUMN_BYTES, 2 * getCharWidth() + fm.boundingRect(sBytes).width());
        setColumnWidth(COLUMN_ARROWS, 5 * getCharWidth());
        setColumnWidth(COLUMN_OPCODE, 40 * getCharWidth());
        setColumnWidth(COLUMN_COMMENT, 60 * getCharWidth());
        setColumnWidth(COLUMN_LABEL, 10 * getCharWidth());

        setColumnEnabled(COLUMN_LABEL, true);
        setColumnEnabled(COLUMN_COMMENT, true);
    } else if (g_viewDisasm == VIEWDISASM_COMPACT) {
        setColumnWidth(COLUMN_BYTES, 10 * getCharWidth());
        setColumnWidth(COLUMN_ARROWS, 2 * getCharWidth());
        setColumnWidth(COLUMN_OPCODE, 40 * getCharWidth());

        setColumnEnabled(COLUMN_LABEL, false);
        setColumnEnabled(COLUMN_COMMENT, false);
    }

#ifndef USE_XPROCESS
    setColumnEnabled(COLUMN_BREAKPOINT, false);
#else
    setColumnWidth(COLUMN_BREAKPOINT, 2 * getCharWidth());
    setColumnEnabled(COLUMN_BREAKPOINT, true);
#endif
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
        // QMenu contextMenu(this); // TODO
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
        dmds.setData(getDevice(), state.nSelectionDeviceOffset, getMemoryMap(), getDisasmCore());

        dmds.exec();
    }
}

void XDisasmView::_hexSlot()
{
    if (g_options.bMenu_Hex) {
        DEVICESTATE state = getDeviceState();

        if (state.nSelectionDeviceOffset != (quint64)-1) {
            emit followLocation(state.nSelectionDeviceOffset, XBinary::LT_OFFSET, state.nSelectionSize, XOptions::WIDGETTYPE_HEX);
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
    // if (getXInfoDB()) {
    //     getXInfoDB()->addAddressForAnalyze();
    // }

    _transfer(XInfoDBTransfer::COMMAND_ANALYZEALL);
}

void XDisasmView::_analyzeAnalyze()
{
    _transfer(XInfoDBTransfer::COMMAND_ANALYZE);
}

void XDisasmView::_analyzeSymbols()
{
    if (getXInfoDB()) {
#ifdef QT_DEBUG
        qDebug("void XDisasmView::_analyzeSymbols()");
#endif
        DialogXSymbols dialogSymbols(this);
        dialogSymbols.setGlobal(getShortcuts(), getGlobalOptions());
        // dialogSymbols.setData(getXInfoDB(), getXInfoProfile(), XSymbolsWidget::MODE_ALL, true);

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
        // dialogSymbols.setData(getXInfoDB(), getXInfoProfile(), XSymbolsWidget::MODE_FUNCTIONS, true);

        connect(&dialogSymbols, SIGNAL(currentSymbolChanged(XADDR, qint64)), this, SLOT(goToAddressSlot(XADDR, qint64)));

        XOptions::_adjustStayOnTop(&dialogSymbols, true);

        dialogSymbols.exec();
    }
}

void XDisasmView::_transfer(XInfoDBTransfer::COMMAND command)
{
    if (getXInfoDB()) {
        STATE state = getState();

        // XADDR nAddress = getAddressByViewPos(state.nSelectionViewPos);  // TODO Offsets ???
        XADDR nAddress = 0;

        if (nAddress != (XADDR)-1) {
            qint64 nViewStart = getViewPosStart();

            DialogXInfoDBTransferProcess dialogTransfer(this);
            dialogTransfer.setGlobal(getShortcuts(), getGlobalOptions());
            XInfoDBTransfer::OPTIONS options = {};
            options.pDevice = getDevice();

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
        // dialogSymbols.setData(getXInfoDB(), getXInfoProfile(), XSymbolsWidget::MODE_REFERENCES, true);

        connect(&dialogSymbols, SIGNAL(currentSymbolChanged(XADDR, qint64)), this, SLOT(goToAddressSlot(XADDR, qint64)));

        XOptions::_adjustStayOnTop(&dialogSymbols, true);

        dialogSymbols.exec();
    }
}
