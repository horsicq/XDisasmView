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
#ifndef XDISASMVIEW_H
#define XDISASMVIEW_H

#include <QTextDocument>
#include "dialogmultidisasmsignature.h"
#include "xcapstone.h"
#include "xdevicetableview.h"

// TODO AbstractQuery
// Load symbols Save db
// TODO Click on Comment Header All -> User Comments -> System Comments
// TODO Click on Opcode label -> Addresses
// TODO click on jmps
// TODO Capstone info
class XDisasmView : public XDeviceTableView
{
    Q_OBJECT

    enum SHORTCUT
    {
        SC_GOTOADDRESS,
        SC_GOTOOFFSET,
        SC_GOTOENTRYPOINT,
        SC_DUMPTOFILE,
        SC_SELECTALL,
        SC_COPYASHEX,
        SC_COPYCURSOROFFSET,
        SC_COPYCURSORADDRESS,
        SC_FIND,
        SC_FINDNEXT,
        SC_HEXSIGNATURE,
        SC_SIGNATURE,
        SC_HEX,
        __SC_SIZE,
        // TODO more
    };

    struct OPCODECOLOR
    {
        QColor colText;
        QColor colBackground;
    };

public:
    struct OPTIONS
    {
        qint64 nInitAddress;
        qint64 nCurrentIPAddress; // For Debugger
        qint64 nEntryPointAddress;
        XBinary::_MEMORY_MAP memoryMap;
        bool bMenu_Hex;
    };

    explicit XDisasmView(QWidget *pParent=nullptr);
    ~XDisasmView();

    void _adjustView();
    void adjustView();
    void setData(QIODevice *pDevice,OPTIONS options,bool bReload=true);
    void setMode(XBinary::DM disasmMode);
    XBinary::DM getMode();
    void setCurrentPointerAddress(XADDR nAddress); // For Debugger
    qint64 getSelectionInitAddress();

private:
    enum COLUMN
    {
        COLUMN_ARROWS=0,
        COLUMN_ADDRESS,
//        COLUMN_OFFSET,
        COLUMN_BYTES,
        COLUMN_OPCODE,
        COLUMN_COMMENT
    };

    enum ARRAY
    {
        ARRAY_NONE=0,
        ARRAY_UP,
        ARRAY_DOWN
    };

    struct DISASM_RESULT
    {
        bool bIsValid;
        XADDR nAddress;
        qint32 nSize;
        QString sMnemonic;
        QString sString;
        bool bRelative;
        XADDR nXrefTo;
        MODE mode;
    };

    struct RECORD
    {
        QString sAddress;
//        QString sOffset;
        QString sHEX;
        QString sCommemt;
        qint64 nOffset;
        XADDR nAddress;
        DISASM_RESULT disasmResult;
        bool bIsReplaced;
        ARRAY array;
        qint32 nArrayLevel;
        qint32 nMaxLevel;
        qint32 nArraySize;
        bool bIsEnd;
        // TODO jmp/jcc
    };

    struct MENU_STATE
    {
//        bool bOffset;
        bool bSize;
        bool bHex;
    };

    enum MODE_OPCODE
    {
        MODE_OPCODE_ORIGINAL=0,
        MODE_OPCODE_SYMBOLADDRESS,
        MODE_OPCODE_SYMBOL,
        MODE_OPCODE_ADDRESS,
    };

    DISASM_RESULT _disasm(char *pData,qint32 nDataSize,quint64 nAddress,MODE mode); // TODO move to XDisasm
    qint64 getDisasmOffset(qint64 nOffset,qint64 nOldOffset);
    MENU_STATE getMenuState();

    struct TEXT_OPTION
    {
        bool bSelected;
        bool bCurrentIP;
        bool bIsReplaced;
        bool bHighlight;
    };

    void drawText(QPainter *pPainter,qint32 nLeft,qint32 nTop,qint32 nWidth,qint32 nHeight,QString sText,TEXT_OPTION *pTextOption);
    void drawDisasmText(QPainter *pPainter,QRect rect,QString sText);
    void drawArrow(QPainter *pPainter, QPointF pointStart, QPointF pointEnd);
    QMap<QString,OPCODECOLOR> getOpcodeColorMap(XBinary::DM disasmMode,XBinary::SYNTAX syntax=XBinary::SYNTAX_DEFAULT);
    OPCODECOLOR getOpcodeColor(XOptions::ID id);

protected:
    virtual OS cursorPositionToOS(CURSOR_POSITION cursorPosition);
    virtual void updateData();
    virtual void paintColumn(QPainter *pPainter,qint32 nColumn,qint32 nLeft,qint32 nTop,qint32 nWidth,qint32 nHeight);
    virtual void paintCell(QPainter *pPainter,qint32 nRow,qint32 nColumn,qint32 nLeft,qint32 nTop,qint32 nWidth,qint32 nHeight);
    virtual void contextMenu(const QPoint &pos);
    virtual void wheelEvent(QWheelEvent *pEvent);
    virtual void keyPressEvent(QKeyEvent *pEvent);
    virtual qint64 getScrollValue();
    virtual void setScrollValue(qint64 nOffset);
    virtual void adjustColumns();
    virtual void registerShortcuts(bool bState);
    virtual void _headerClicked(qint32 nColumn);
    virtual void _cellDoubleClicked(qint32 nRow,qint32 nColumn);
    virtual qint64 getRecordSize(qint64 nOffset);

protected slots:
    void _goToEntryPointSlot();
    void _signatureSlot();
    void _hexSlot();

private:
    OPTIONS g_options;
    qint32 g_nBytesProLine;
    QList<RECORD> g_listRecords;

//    QList<ARROW> g_listArrows;
    XBinary::DM g_disasmMode;
    csh g_handle;

    QShortcut *shortCuts[__SC_SIZE];

    qint32 g_nAddressWidth;
    qint32 g_nOpcodeSize;

    // Debugger
    XADDR g_nCurrentIP;

    QMap<QString,OPCODECOLOR> g_mapOpcodes;
    XBinary::SYNTAX g_syntax;

    XADDR g_nThisBase;
    bool g_bIsAddressColon;
    bool g_bIsHighlight;
    MODE_OPCODE g_modeOpcode;
};

#endif // XDISASMVIEW_H
