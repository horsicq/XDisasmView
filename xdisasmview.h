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
#ifndef XDISASMVIEW_H
#define XDISASMVIEW_H

#include <QTextDocument>

#include "dialoghexedit.h"
#include "dialogmultidisasmsignature.h"
#include "xcapstone.h"
#include "xdevicetableeditview.h"

// TODO AbstractQuery
// Load symbols Save db
// TODO Click on Comment Header All -> User Comments -> System Comments
// TODO Click on Opcode label -> Addresses
// TODO click on jmps
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
        __SC_SIZE,
        // TODO more
    };

    struct OPCODECOLOR {
        QColor colText;
        QColor colBackground;
    };

public:
    struct OPTIONS {
        XADDR nInitAddress;
        XADDR nEntryPointAddress;  // TODO move to xdb
        XBinary::_MEMORY_MAP memoryMapRegion;
        bool bAprox;
        bool bMenu_Hex;
    };

    explicit XDisasmView(QWidget *pParent = nullptr);
    ~XDisasmView();

    void _adjustView();
    void adjustView();
    void setData(QIODevice *pDevice, OPTIONS options, bool bReload = true);
    void setMode(XBinary::DM disasmMode);
    XBinary::DM getMode();
    XADDR getSelectionInitAddress();
    DEVICESTATE getDeviceState(bool bGlobalOffset = false);
    void setDeviceState(DEVICESTATE deviceState, bool bGlobalOffset = false);
    virtual qint64 deviceOffsetToViewOffset(qint64 nOffset, bool bGlobalOffset = false);
    virtual qint64 deviceSizeToViewSize(qint64 nOffset, qint64 nSize, bool bGlobalOffset = false);

private:
    enum COLUMN {
        COLUMN_ARROWS = 0,
        COLUMN_LOCATION,
        COLUMN_BYTES,
        COLUMN_OPCODE,
        COLUMN_COMMENT
    };

    enum ARRAY {
        ARRAY_NONE = 0,
        ARRAY_UP,
        ARRAY_DOWN
    };

    struct RECORD {
        QString sLocation;
        QString sBytes;  // mb TODO labels
        QString sComment;
        qint64 nViewOffset;  // Line if file analyzed or FileOffset if not
        XADDR nVirtualAddress;
        qint64 nDeviceOffset;
        XCapstone::DISASM_RESULT disasmResult;
        bool bIsBreakpoint;
        bool bIsCurrentIP;
        ARRAY array;
        qint32 nArrayLevel;
        qint32 nMaxLevel;
        qint32 nArraySize;
        bool bIsEnd;
        // TODO jmp/jcc
    };

    struct MENU_STATE {
        //        bool bOffset;
        bool bSize;
        bool bHex;
    };

    enum MODE_OPCODE {
        MODE_OPCODE_ORIGINAL = 0,
        MODE_OPCODE_SYMBOLADDRESS,
        MODE_OPCODE_SYMBOL,
        MODE_OPCODE_ADDRESS,
    };

    XCapstone::DISASM_RESULT _disasm(XADDR nVirtualAddress, char *pData, qint32 nDataSize);
    QString convertOpcodeString(XCapstone::DISASM_RESULT disasmResult);
    qint64 getDisasmViewOffset(qint64 nViewOffset, qint64 nOldViewOffset);
    MENU_STATE getMenuState();

    struct TEXT_OPTION {
        bool bIsSelected;
        bool bIsCurrentIP;
        //        bool bIsCursor;
        bool bIsBreakpoint;
        bool bHighlight;
    };

    void drawText(QPainter *pPainter, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight, QString sText, TEXT_OPTION *pTextOption);
    void drawDisasmText(QPainter *pPainter, QRect rect, QString sText);
    void drawArrow(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond);
    void drawLine(QPainter *pPainter, QPointF pointStart, QPointF pointEnd, bool bIsSelected, bool bIsCond);
    QMap<QString, OPCODECOLOR> getOpcodeColorMap(XBinary::DM disasmMode, XBinary::SYNTAX syntax = XBinary::SYNTAX_DEFAULT);
    OPCODECOLOR getOpcodeColor(XOptions::ID id);

private:
    RECORD _getRecordByViewOffset(QList<RECORD> *pListRecord, qint64 nViewOffset);
    RECORD _getRecordByVirtualAddress(QList<RECORD> *pListRecord, XADDR nVirtualAddress);

protected:
    virtual OS cursorPositionToOS(CURSOR_POSITION cursorPosition);
    virtual void updateData();
    virtual void paintColumn(QPainter *pPainter, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight);
    virtual void paintCell(QPainter *pPainter, qint32 nRow, qint32 nColumn, qint32 nLeft, qint32 nTop, qint32 nWidth, qint32 nHeight);
    virtual void contextMenu(const QPoint &pos);
    virtual void wheelEvent(QWheelEvent *pEvent);
    virtual void keyPressEvent(QKeyEvent *pEvent);
    virtual qint64 getCurrentLineFromScroll();
    virtual void setCurrentViewOffsetToScroll(qint64 nViewOffset);
    virtual void adjustColumns();
    virtual void registerShortcuts(bool bState);
    virtual void _headerClicked(qint32 nColumn);
    virtual void _cellDoubleClicked(qint32 nRow, qint32 nColumn);
    virtual qint64 getFixViewOffset(qint64 nViewOffset);
    virtual void adjustLineCount();
    virtual void adjustViewSize();  // TODO remove
    virtual qint64 getViewSizeByOffset(qint64 nViewOffset);
    virtual qint64 addressToViewOffset(XADDR nAddress);

protected slots:
    void _goToEntryPointSlot();
    void _goToXrefSlot();
    void _signatureSlot();
    void _hexSlot();

signals:
    void showOffsetHex(qint64 nOffset);  // TODO Offset/Size

private:
    OPTIONS g_options;
    qint32 g_nBytesProLine;
    QList<RECORD> g_listRecords;
    XBinary::DM g_disasmMode;
    csh g_handle;

    QShortcut *shortCuts[__SC_SIZE];

    qint32 g_nAddressWidth;
    qint32 g_nOpcodeSize;
    QMap<QString, OPCODECOLOR> g_mapOpcodeColorMap;
    XBinary::SYNTAX g_syntax;
    XADDR g_nThisBase;
    bool g_bIsAddressColon;
    bool g_bIsUppercase;
    bool g_bIsHighlight;
    MODE_OPCODE g_modeOpcode;
    QTextOption _qTextOptions;
    XCapstone::DISASM_OPTIONS g_disasmOptions;
};

#endif  // XDISASMVIEW_H
