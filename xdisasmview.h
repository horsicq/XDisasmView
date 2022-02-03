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
#include "xcapstone.h"
#include "xdevicetableview.h"
#include "dialogmultidisasmsignature.h"

// TODO AbstractQuery
// Load symbols Save db
// TODO Click on Comment Header All -> User Comments -> System Comments
// TODO click on jmps
class XDisasmView : public XDeviceTableView
{
    Q_OBJECT

    enum SHORTCUT
    {
        SHORTCUT_GOTOADDRESS,
        SHORTCUT_GOTOOFFSET,
        SHORTCUT_GOTOENTRYPOINT,
        SHORTCUT_DUMPTOFILE,
        SHORTCUT_SELECTALL,
        SHORTCUT_COPYASHEX,
        SHORTCUT_COPYCURSOROFFSET,
        SHORTCUT_COPYCURSORADDRESS,
        SHORTCUT_FIND,
        SHORTCUT_FINDNEXT,
        SHORTCUT_HEXSIGNATURE,
        SHORTCUT_SIGNATURE,
        SHORTCUT_HEX,
        SHORTCUT__SIZE,
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

    void adjustView();
    void setData(QIODevice *pDevice,OPTIONS options);
    void setMode(XBinary::DM disasmMode,XBinary::SYNTAX syntax=XBinary::SYNTAX_DEFAULT);
    XBinary::DM getMode();
    void setCurrentIPAddress(qint64 nAddress); // For Debugger
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

    struct DISASM_RESULT
    {
        bool bIsValid;
        qint64 nAddress;
        qint32 nSize;
        QString sMnemonic;
        QString sString;
        qint64 nXrefTo;
    };

    struct RECORD
    {
        QString sAddress;
//        QString sOffset;
        QString sHEX;
        QString sCommemt;
        qint64 nOffset;
        DISASM_RESULT disasmResult;
        bool bIsReplaced;
    };

//    struct ARROW
//    {
//        qint64 nFrom;
//        qint64 nTo;
//        qint32 nLevel;
//    };

    struct MENU_STATE
    {
//        bool bOffset;
        bool bSize;
        bool bHex;
    };

    DISASM_RESULT _disasm(char *pData,qint32 nDataSize,qint64 nAddress); // TODO move to XDisasm
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
    QMap<QString,OPCODECOLOR> getOpcodeColorMap(XBinary::DM disasmMode,XBinary::SYNTAX syntax=XBinary::SYNTAX_DEFAULT);
    OPCODECOLOR getOpcodeColor(XOptions::ID idText,XOptions::ID idBackground);

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

    QShortcut *shortCuts[SHORTCUT__SIZE];

    qint32 g_nAddressWidth;
    qint32 g_nOpcodeSize;

    // Debugger
    qint64 g_nCurrentIP;

    QMap<QString,OPCODECOLOR> g_mapOpcodes;

    qint64 g_nThisBase;
};

#endif // XDISASMVIEW_H
