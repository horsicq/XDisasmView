include_directories(${CMAKE_CURRENT_LIST_DIR})

if (NOT DEFINED XFORMATS_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xformats.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${XFORMATS_SOURCES})
endif()
if (NOT DEFINED XABSTRACTTABLEVIEW_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../Controls/xabstracttableview.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${XABSTRACTTABLEVIEW_SOURCES})
endif()
if (NOT DEFINED XCAPSTONE_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XCapstone/xcapstone.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${XCAPSTONE_SOURCES})
endif()
if (NOT DEFINED DIALOGGOTOADDRESS_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../FormatDialogs/dialoggotoaddress.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${DIALOGGOTOADDRESS_SOURCES})
endif()
if (NOT DEFINED DIALOGSEARCH_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../FormatDialogs/dialogsearch.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${DIALOGSEARCH_SOURCES})
endif()
if (NOT DEFINED DIALOGDUMP_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../FormatDialogs/dialogdump.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${DIALOGDUMP_SOURCES})
endif()
if (NOT DEFINED DIALOGHEXSIGNATURE_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../FormatDialogs/dialoghexsignature.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${DIALOGHEXSIGNATURE_SOURCES})
endif()
if (NOT DEFINED SEARCHSIGNATURESWIDGET_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../FormatWidgets/SearchSignatures/searchsignatureswidget.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${SEARCHSIGNATURESWIDGET_SOURCES})
endif()
if (NOT DEFINED XHEXEDIT_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XHexEdit/xhexedit.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${XHEXEDIT_SOURCES})
endif()
if (NOT DEFINED XSYMBOLSWIDGET_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XSymbolsWidget/xsymbolswidget.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${XSYMBOLSWIDGET_SOURCES})
endif()
if (NOT DEFINED XDECOMPILER_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XDecompiler/xdecompiler.cmake)
    set(XDISASMVIEW_SOURCES ${XDISASMVIEW_SOURCES} ${XDECOMPILER_SOURCES})
endif()

set(XDISASMVIEW_SOURCES
    ${XDISASMVIEW_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/dialogmultidisasm.cpp
    ${CMAKE_CURRENT_LIST_DIR}/dialogmultidisasm.h
    ${CMAKE_CURRENT_LIST_DIR}/dialogmultidisasm.ui
    ${CMAKE_CURRENT_LIST_DIR}/Widgets/dialogmultidisasmsignature.cpp
    ${CMAKE_CURRENT_LIST_DIR}/Widgets/dialogmultidisasmsignature.h
    ${CMAKE_CURRENT_LIST_DIR}/Widgets/dialogmultidisasmsignature.ui
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmview.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmview.h
    ${CMAKE_CURRENT_LIST_DIR}/xmultidisasmwidget.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xmultidisasmwidget.h
    ${CMAKE_CURRENT_LIST_DIR}/xmultidisasmwidget.ui
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmviewoptionswidget.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmviewoptionswidget.h
    ${CMAKE_CURRENT_LIST_DIR}/xdisasmviewoptionswidget.ui
)
