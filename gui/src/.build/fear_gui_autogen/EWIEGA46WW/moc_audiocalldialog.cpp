/****************************************************************************
** Meta object code from reading C++ file 'audiocalldialog.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.4.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../audiocalldialog.h"
#include <QtGui/qtextcursor.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'audiocalldialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.4.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
namespace {
struct qt_meta_stringdata_AudioCallDialog_t {
    uint offsetsAndSizes[30];
    char stringdata0[16];
    char stringdata1[14];
    char stringdata2[1];
    char stringdata3[15];
    char stringdata4[4];
    char stringdata5[12];
    char stringdata6[17];
    char stringdata7[11];
    char stringdata8[14];
    char stringdata9[14];
    char stringdata10[8];
    char stringdata11[6];
    char stringdata12[9];
    char stringdata13[7];
    char stringdata14[20];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_AudioCallDialog_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_AudioCallDialog_t qt_meta_stringdata_AudioCallDialog = {
    {
        QT_MOC_LITERAL(0, 15),  // "AudioCallDialog"
        QT_MOC_LITERAL(16, 13),  // "onGenerateKey"
        QT_MOC_LITERAL(30, 0),  // ""
        QT_MOC_LITERAL(31, 14),  // "onKeyGenerated"
        QT_MOC_LITERAL(46, 3),  // "key"
        QT_MOC_LITERAL(50, 11),  // "onStartCall"
        QT_MOC_LITERAL(62, 16),  // "onStartListening"
        QT_MOC_LITERAL(79, 10),  // "onStopCall"
        QT_MOC_LITERAL(90, 13),  // "onCallStarted"
        QT_MOC_LITERAL(104, 13),  // "onCallStopped"
        QT_MOC_LITERAL(118, 7),  // "onError"
        QT_MOC_LITERAL(126, 5),  // "error"
        QT_MOC_LITERAL(132, 8),  // "onOutput"
        QT_MOC_LITERAL(141, 6),  // "output"
        QT_MOC_LITERAL(148, 19)   // "refreshAudioDevices"
    },
    "AudioCallDialog",
    "onGenerateKey",
    "",
    "onKeyGenerated",
    "key",
    "onStartCall",
    "onStartListening",
    "onStopCall",
    "onCallStarted",
    "onCallStopped",
    "onError",
    "error",
    "onOutput",
    "output",
    "refreshAudioDevices"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_AudioCallDialog[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
      10,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,   74,    2, 0x08,    1 /* Private */,
       3,    1,   75,    2, 0x08,    2 /* Private */,
       5,    0,   78,    2, 0x08,    4 /* Private */,
       6,    0,   79,    2, 0x08,    5 /* Private */,
       7,    0,   80,    2, 0x08,    6 /* Private */,
       8,    0,   81,    2, 0x08,    7 /* Private */,
       9,    0,   82,    2, 0x08,    8 /* Private */,
      10,    1,   83,    2, 0x08,    9 /* Private */,
      12,    1,   86,    2, 0x08,   11 /* Private */,
      14,    0,   89,    2, 0x08,   13 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    4,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   11,
    QMetaType::Void, QMetaType::QString,   13,
    QMetaType::Void,

       0        // eod
};

Q_CONSTINIT const QMetaObject AudioCallDialog::staticMetaObject = { {
    QMetaObject::SuperData::link<QDialog::staticMetaObject>(),
    qt_meta_stringdata_AudioCallDialog.offsetsAndSizes,
    qt_meta_data_AudioCallDialog,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_AudioCallDialog_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<AudioCallDialog, std::true_type>,
        // method 'onGenerateKey'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onKeyGenerated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'onStartCall'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onStartListening'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onStopCall'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onCallStarted'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onCallStopped'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onError'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'onOutput'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'refreshAudioDevices'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void AudioCallDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<AudioCallDialog *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->onGenerateKey(); break;
        case 1: _t->onKeyGenerated((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 2: _t->onStartCall(); break;
        case 3: _t->onStartListening(); break;
        case 4: _t->onStopCall(); break;
        case 5: _t->onCallStarted(); break;
        case 6: _t->onCallStopped(); break;
        case 7: _t->onError((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 8: _t->onOutput((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 9: _t->refreshAudioDevices(); break;
        default: ;
        }
    }
}

const QMetaObject *AudioCallDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *AudioCallDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_AudioCallDialog.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int AudioCallDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 10)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 10;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 10)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 10;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
