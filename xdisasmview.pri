INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/dialogmultidisasm.h \
    $$PWD/dialogmultidisasmsignature.h \
    $$PWD/xdisasmview.h \
    $$PWD/xmultidisasmwidget.h

SOURCES += \
    $$PWD/dialogmultidisasm.cpp \
    $$PWD/dialogmultidisasmsignature.cpp \
    $$PWD/xdisasmview.cpp \
    $$PWD/xmultidisasmwidget.cpp

FORMS += \
    $$PWD/dialogmultidisasm.ui \
    $$PWD/dialogmultidisasmsignature.ui \
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

!contains(XCONFIG, dialoghexsignature) {
    XCONFIG += dialoghexsignature
    include($$PWD/../FormatDialogs/dialoghexsignature.pri)
}
