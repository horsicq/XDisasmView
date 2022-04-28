INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/dialogmultidisasm.h \
    $$PWD/dialogmultidisasmsignature.h \
    $$PWD/dialogxdisasmviewcolors.h \
    $$PWD/xdisasmview.h \
    $$PWD/xdisasmviewoptionswidget.h \
    $$PWD/xmultidisasmwidget.h

SOURCES += \
    $$PWD/dialogmultidisasm.cpp \
    $$PWD/dialogmultidisasmsignature.cpp \
    $$PWD/dialogxdisasmviewcolors.cpp \
    $$PWD/xdisasmview.cpp \
    $$PWD/xdisasmviewoptionswidget.cpp \
    $$PWD/xmultidisasmwidget.cpp

FORMS += \
    $$PWD/dialogmultidisasm.ui \
    $$PWD/dialogmultidisasmsignature.ui \
    $$PWD/dialogxdisasmviewcolors.ui \
    $$PWD/xdisasmviewoptionswidget.ui \
    $$PWD/xmultidisasmwidget.ui

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

!contains(XCONFIG, xabstracttableview) {
    XCONFIG += xabstracttableview
    include($$PWD/../Controls/xabstracttableview.pri)
}

!contains(XCONFIG, xcapstone) {
    XCONFIG += xcapstone
    include($$PWD/../XCapstone/xcapstone.pri)
}

!contains(XCONFIG, dialoggotoaddress) {
    XCONFIG += dialoggotoaddress
    include($$PWD/../FormatDialogs/dialoggotoaddress.pri)
}

!contains(XCONFIG, dialogsearch) {
    XCONFIG += dialogsearch
    include($$PWD/../FormatDialogs/dialogsearch.pri)
}

!contains(XCONFIG, dialogdump) {
    XCONFIG += dialogdump
    include($$PWD/../FormatDialogs/dialogdump.pri)
}

!contains(XCONFIG, searchsignatureswidget) {
    XCONFIG += searchsignatureswidget
    include($$PWD/../FormatWidgets/SearchSignatures/searchsignatureswidget.pri)
}

!contains(XCONFIG, dialoghexsignature) {
    XCONFIG += dialoghexsignature
    include($$PWD/../FormatDialogs/dialoghexsignature.pri)
}

!contains(XCONFIG, xhexedit) {
    XCONFIG += xhexedit
    include($$PWD/../XHexEdit/xhexedit.pri)
}

!contains(XCONFIG, dialogxinfodbtransferprocess) {
    XCONFIG += dialogxinfodbtransferprocess
    include($$PWD/../XInfoDB/dialogxinfodbtransferprocess.pri)
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xdisasmview.cmake
