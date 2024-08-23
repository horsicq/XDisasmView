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
#ifndef XDISASMVIEW_H
#define XDISASMVIEW_H

#include <QTextDocument>

#include "dialoghexedit.h"
#include "dialogmultidisasmsignature.h"
#include "xcapstone.h"
#include "xdevicetableeditview.h"
#include "dialogxsymbols.h"
#include "dialogxinfodbtransferprocess.h"

// TODO AbstractQuery
// Load symbols Save db
// TODO Click on Comment Header All -> User Comments -> System Comments
// TODO Click on Opcode label -> Addresses
// TODO Capstone info
class XDisasmView : public XDeviceTableEditView {
    Q_OBJECT

    enum SHORTCUT {
        SC_GOTOADDRESS,
        SC_GOTOOFFSET,
        SC_GOTOENTRYPOINT,
        SC_GOTOXREF,
        SC_DUMPTOFILE,
        SC_SELECTALL,
        SC_COPYDATA,
        SC_COPYADDRESS,
        SC_COPYOFFSET,
        SC_FIND_STRING,
        SC_FIND_SIGNATURE,
        SC_FIND_VALUE,
        SC_FINDNEXT,
        SC_HEXSIGNATURE,
        SC_SIGNATURE,
        SC_FOLLOWIN_HEX,
        SC_EDIT_HEX,
#ifdef QT_SQL_LIB
        SC_ANALYZE_ALL,
        SC_ANALYZE_ANALYZE,
        SC_ANALYZE_DISASM,
        SC_ANALYZE_REMOVE,
        SC_ANALYZE_SYMBOLS,
        SC_ANALYZE_FUNCTIONS,
#endif
        __SC_SIZE,
        // TODO more
    };

    struct COLOR_RECORD {
        QColor colMain;
        QColor colBackground;
    };

    struct VIEWSTRUCT {
        qint64 nScrollStart;
        qint64 nScrollCount;
        qint64 nViewPos;
        XADDR nAddress;
        qint64 nOffset;
        qint64 nSize;
    };

    struct TRANSRECORD {
        qint64 nViewPos;
        XADDR nAddress;
        qint64 nOffset;
        qint64 nSize;
    };

public:
    struct OPTIONS {
        XADDR nInitAddress;
        XADDR nEntryPointAddress;  // TODO move to xdb
        XBinary::_MEMORY_MAP memoryMapRegion;
        XBinary::DM disasmMode;
        bool bAprox;
        bool bMenu_Hex;
        bool bHideReadOnly;
    };

    explicit XDisasmView(QWidget *pParent = nullptr);
    ~XDisasmView();

    void _adjustView();
    virtual void adjustView();
    void setData(QIODevice *pDevice, const OPTIONS &options, bool bReload = true);
    OPTIONS getOptions();
    XBinary::DM getDisasmMode();
    XADDR getSelectionInitAddress();
    DEVICESTATE getDeviceState(bool bGlobalOffset = false);
    void setDeviceState(const DEVICESTATE &deviceState, bool bGlobalOffset = false);
    virtual qint64 deviceOffsetToViewPos(qint64 nOffset, bool bGlobalOffset = false);
    virtual qint64 deviceSizeToViewSize(qint64 nOffset, qint64 nSize, bool bGlobalOffset = false);
    virtual qint64 viewPosToDeviceOffset(qint64 nViewPos, bool bGlobalOffset = false);
    void showReferences(XADDR nAddress);

private:
    enum COLUMN {
        COLUMN_ARROWS = 0,
        COLUMN_BREAKPOINT,
        COLUMN_LOCATION,
        COLUMN_LABEL,
        COLUMN_BYTES,
        COLUMN_OPCODE,
        COLUMN_COMMENT
    };

    enum ARROW {
        ARROW_NONE = 0,
        ARROW_UP,
        ARROW_DOWN
    };

    struct RECORD {
        QString sLocation;
        QString sBytes;
        QString sLabel;
        QString sComment;
        qint64 nViewPos;  // Line
        XADDR nVirtualAddress;
        qint64 nDeviceOffset;
        XCapstone::DISASM_RESULT disasmResult;
#ifdef USE_XPROCESS
        XInfoDB::BPT breakpointType;
        bool bIsCurrentIP;
#endif
        bool bIsAnalysed;
        ARROW array;
        qint32 nArrayLevel;
        qint32 nMaxLevel;
        qint32 nArraySize;
        bool bIsEnd;
        bool bHasRefFrom;
        bool bIsBytesHighlighted;
        QColor colBytesBackground;
        QColor colBytesBackgroundSelected;
        quint32 nInfo;
        bool bIsAprox;  // TODO mb red color!!!
        // TODO jmp/jcc
    };

    struct MENU_STATE {
        //        bool bOffset;
        bool bPhysicalSize;
        bool bSize;
        bool bHex;
    };

    // enum OPCODEMODE {
    //     OPCODEMODE_ORIGINAL = 0,
    //     OPCODEMODE_SYMBOLADDRESS,
    //     OPCODEMODE_SYMBOL,
    //     OPCODEMODE_ADDRESS,
    // };

    //    enum BYTESMODE {
    //        BYTESMODE_RAW = 0,
    //    };

    QString convertOpcodeString(const XCapstone::DISASM_RESULT &disasmResult);
    qint64 getDisasmViewPos(qint64 nViewPos, qint64 nOldViewPos);  // TODO rename
    MENU_STATE getMenuState();

    struct TEXT_OPTION {
        bool bIsSelected;
        bool bIsCurrentIP;
        //        bool bIsCursor;
        bool bIsBreakpoint;
        bool bASMHighlight;
        bool bIsAnalysed;
        QColor colSelected;
        QColor colBreakpoint;
        QColor colAnalyzed;
    };

    void drawText(QPainter *pPainter, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight, const QString &sText, TEXT_OPTION *pTextOption);
    void drawAsmText(QPainter *pPainter, const QRect &rect, const QString &sText);
    void drawColorText(QPainter *pPainter, const QRect &rect, const QString &sText, const COLOR_RECORD &colorRecord);
    void drawArg(QPainter *pPainter, const QRect &rect, const QString &sText);
    void drawArrowHead(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond);
    void drawArrowLine(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond);
    QMap<XOptions::ID, COLOR_RECORD> getColorRecordsMap();
    COLOR_RECORD getColorRecord(XOptions::ID id);
    COLOR_RECORD getOpcodeColor(const QString &sOpcode);
    COLOR_RECORD getOperandColor(const QString &sOperand);

private:
    RECORD _getRecordByViewPos(QList<RECORD> *pListRecord, qint64 nViewPos);
    RECORD _getRecordByVirtualAddress(QList<RECORD> *pListRecord, XADDR nVirtualAddress);
    VIEWSTRUCT _getViewStructByOffset(qint64 nOffset);
    VIEWSTRUCT _getViewStructByAddress(XADDR nAddress);
    // VIEWSTRUCT _getViewStructByScroll(qint64 nValue);
    VIEWSTRUCT _getViewStructByViewPos(qint64 nViewPos);
    QList<TRANSRECORD> _getTransRecords(qint64 nViewPos, qint64 nSize);
    qint64 _getOffsetByViewPos(qint64 nViewPos);
    qint64 _getViewPosByAddress(XADDR nAddress);
    XADDR _getAddressByViewPos(qint64 nViewPos);

protected:
    virtual OS cursorPositionToOS(const CURSOR_POSITION &cursorPosition);
    virtual void updateData();
    virtual void paintColumn(QPainter *pPainter, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight);
    virtual void paintCell(QPainter *pPainter, qint32 nRow, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight);
    virtual void contextMenu(const QPoint &pos);
    virtual void wheelEvent(QWheelEvent *pEvent);
    virtual void keyPressEvent(QKeyEvent *pEvent);
    virtual qint64 getCurrentViewPosFromScroll();
    virtual void setCurrentViewPosToScroll(qint64 nViewPos);
    virtual void adjustColumns();
    virtual void registerShortcuts(bool bState);
    virtual void _headerClicked(qint32 nColumn);
    virtual void _cellDoubleClicked(qint32 nRow, qint32 nColumn);
    virtual qint64 getFixViewPos(qint64 nViewPos);  // TODO rewrite
    virtual void adjustScrollCount();
    virtual qint64 getViewSizeByViewPos(qint64 nViewPos);  // TODO rewrite
    virtual qint64 addressToViewPos(XADDR nAddress);

protected slots:
    void _goToEntryPointSlot();
    void _goToXrefSlot();
    void _signatureSlot();
    void _hexSlot();
    void _referencesSlot();
    void _analyzeAll();
    void _analyzeAnalyze();
    void _analyzeDisasm();
    void _analyzeRemove();
    void _analyzeClear();
    void _analyzeSymbols();
    void _analyzeFunctions();
    void _transfer(XInfoDBTransfer::COMMAND command);

signals:
    void showOffsetHex(qint64 nOffset);  // TODO Offset/Size

private:
    OPTIONS g_options;
    qint32 g_nBytesProLine;
    QList<RECORD> g_listRecords;
    csh g_handle;
    QShortcut *g_shortCuts[__SC_SIZE];
    qint32 g_nAddressWidth;
    qint32 g_nOpcodeSize;
    QMap<XOptions::ID, COLOR_RECORD> g_mapColors;
    XBinary::SYNTAX g_syntax;
    XBinary::DMFAMILY g_dmFamily;
    XADDR g_nThisBaseVirtualAddress;
    qint64 g_nThisBaseDeviceOffset;
    bool g_bIsLocationColon;
    bool g_bIsHighlight;
    // OPCODEMODE g_opcodeMode;
    //    BYTESMODE g_bytesMode;
    QTextOption _qTextOptions;
    XCapstone::DISASM_OPTIONS g_disasmOptions;  // TODO Check remove
    QList<VIEWSTRUCT> g_listViewStruct;
    QList<HIGHLIGHTREGION> g_listHighlightsRegion;
};

#endif  // XDISASMVIEW_H
