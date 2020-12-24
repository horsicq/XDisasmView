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
    $$PWD/dialogmultidisasm.ui \
    $$PWD/dialogmultidisasmsignature.ui \
    $$PWD/xmultidisasmwidget.ui
