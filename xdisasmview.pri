INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xdisasmview.h \
    $$PWD/xmultidisasmwidget.h

SOURCES += \
    $$PWD/xdisasmview.cpp \
    $$PWD/xmultidisasmwidget.cpp

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

FORMS += \
    $$PWD/xmultidisasmwidget.ui
