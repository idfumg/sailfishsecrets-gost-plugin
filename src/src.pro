TEMPLATE = lib

QT -= gui
QT += dbus

QT_CONFIG -= no-pkg-config
CONFIG += plugin c++11 rtti_off qt link_pkgconfig warn_on debug
PKGCONFIG += sailfishcryptopluginapi openssl-helper

unix|macx {
    QMAKE_CXXFLAGS += -Wall -Wextra -Werror -pedantic
}

TARGET = sailfishgostplugin
TARGET = $$qtLibraryTarget($$TARGET)

HEADERS += $$PWD/gostplugin.h
SOURCES += $$PWD/gostplugin.cpp

target.path=/usr/lib/Sailfish/Crypto/
INSTALLS += target
