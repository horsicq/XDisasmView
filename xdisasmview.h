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
#ifndef XDISASMVIEW_H
#define XDISASMVIEW_H

#include <QTextDocument>

#include "dialoghexedit.h"
#include "Widgets/dialogmultidisasmsignature.h"
#include "xdevicetableeditview.h"
#include "dialogxsymbols.h"
#include "xdialogprocess.h"

// TODO AbstractQuery
// Load symbols Save db
// TODO Click on Comment Header All -> User Comments -> System Comments
// TODO Click on Opcode label -> Addresses
// TODO Capstone info
class XDisasmView : public XDeviceTableEditView {
    Q_OBJECT

    struct TRANSRECORD {
        qint64 nViewPos;
        XADDR nAddress;
        qint64 nOffset;
        qint64 nSize;
    };

public:
    enum VIEWMETHOD {
        VIEWMETHOD_NONE = 0,
        VIEWMETHOD_ANALYZED
    };

    enum VIEWDISASM {
        VIEWDISASM_COMPACT = 0,
        VIEWDISASM_FULL
    };

    struct OPTIONS {
        XADDR nInitAddress;
        XADDR nEntryPointAddress;  // TODO move to xdb
        XBinary::FT fileType;
        XBinary::DM disasmMode;
        bool bAprox;
        bool bMenu_Hex;
        bool bHideReadOnly;
    };

    explicit XDisasmView(QWidget *pParent = nullptr);
    ~XDisasmView();

    virtual void adjustView();
    void setData(QIODevice *pDevice, const OPTIONS &options, bool bReload = true);
    void setViewMethod(VIEWMETHOD viewMethod);
    void setViewDisasm(VIEWDISASM viewDisasm);
    OPTIONS getOptions();
    XBinary::DM getDisasmMode();  // TODO Check -> remove
    XADDR getSelectionInitAddress();
    DEVICESTATE getDeviceState(bool bGlobalOffset = false);
    void setDeviceState(const DEVICESTATE &deviceState, bool bGlobalOffset = false);
    // virtual qint64 deviceOffsetToViewPos(qint64 nOffset, bool bGlobalOffset = false);
    // virtual qint64 deviceSizeToViewSize(qint64 nOffset, qint64 nSize, bool bGlobalOffset = false);
    // virtual qint64 viewPosToDeviceOffset(qint64 nViewPos, bool bGlobalOffset = false);
    void showReferences(XADDR nAddress);

    void analyzeAll();

    virtual QList<XShortcuts::MENUITEM> getMenuItems();

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
        qint64 nDeviceOffset;
        XDisasmAbstract::DISASM_RESULT disasmResult;
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

    QString convertOpcodeString(const XDisasmAbstract::DISASM_RESULT &disasmResult);
    qint64 getDisasmViewPos(qint64 nViewPos, qint64 nOldViewPos);  // TODO rename
    MENU_STATE getMenuState();

    struct TEXT_OPTION {
        bool bIsSelected;
        bool bIsCurrentIP;
        //        bool bIsCursor;
        bool bIsBreakpoint;
        bool bIsAnalysed;
        QColor colSelected;
        QColor colBreakpoint;
        QColor colAnalyzed;
    };

    void drawText(QPainter *pPainter, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight, const QString &sText, TEXT_OPTION *pTextOption);
    void drawDisasmText(QPainter *pPainter, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight, const XDisasmAbstract::DISASM_RESULT &disasmResult,
                        TEXT_OPTION *pTextOption);
    void drawArrowHead(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond);
    void drawArrowLine(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond);

private:
    RECORD _getRecordByViewPos(QList<RECORD> *pListRecord, qint64 nViewPos);
    RECORD _getRecordByVirtualAddress(QList<RECORD> *pListRecord, XADDR nVirtualAddress);

    QList<TRANSRECORD> _getTransRecords(qint64 nViewPos, qint64 nSize);
    void getRecords();
    void updateArrows();
    void updateLocations();

protected:
    virtual OS cursorPositionToOS(const CURSOR_POSITION &cursorPosition);
    virtual void updateData();
    virtual void paintColumn(QPainter *pPainter, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight);
    virtual void paintCell(QPainter *pPainter, qint32 nRow, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight);
    virtual void wheelEvent(QWheelEvent *pEvent);
    virtual void keyPressEvent(QKeyEvent *pEvent);
    virtual qint64 getCurrentViewPosFromScroll();
    virtual void setCurrentViewPosToScroll(qint64 nViewPos);
    virtual void adjustColumns();
    virtual void _headerClicked(qint32 nColumn);
    virtual void _cellDoubleClicked(qint32 nRow, qint32 nColumn);
    virtual qint64 getFixViewPos(qint64 nViewPos);  // TODO rewrite
    virtual void adjustScrollCount();
    virtual qint64 getViewSizeByViewPos(qint64 nViewPos);  // TODO rewrite

protected slots:
    void _goToEntryPointSlot();
    void _goToXrefSlot();
    void _signatureSlot();
    void _hexSlot();
    void _referencesSlot();
    void _analyzeAll();
    void _analyzeAnalyze();
    void _analyzeSymbols();
    void _analyzeFunctions();
    void _transfer(XInfoDBTransfer::COMMAND command);

private:
    OPTIONS m_options;
    qint32 m_nBytesProLine;
    QList<RECORD> m_listRecords;
    qint32 m_nAddressWidth;
    qint32 m_nOpcodeSize;
    XADDR m_nThisBaseVirtualAddress;
    qint64 m_nThisBaseDeviceOffset;
    bool m_bIsLocationColon;
    bool m_bIsHighlight;
    // OPCODEMODE g_opcodeMode;
    //    BYTESMODE g_bytesMode;
    QTextOption _qTextOptions;
    XDisasmAbstract::DISASM_OPTIONS m_disasmOptions;

    QList<HIGHLIGHTREGION> m_listHighlightsRegion;
    VIEWMETHOD m_viewMethod;
    VIEWDISASM m_viewDisasm;
};

#endif  // XDISASMVIEW_H
