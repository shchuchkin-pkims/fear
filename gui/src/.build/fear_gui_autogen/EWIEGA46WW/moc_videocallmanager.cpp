/****************************************************************************
** Meta object code from reading C++ file 'videocallmanager.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.4.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../videocallmanager.h"
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'videocallmanager.h' doesn't include <QObject>."
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
struct qt_meta_stringdata_VideoCallManager_t {
    uint offsetsAndSizes[32];
    char stringdata0[17];
    char stringdata1[13];
    char stringdata2[1];
    char stringdata3[4];
    char stringdata4[12];
    char stringdata5[17];
    char stringdata6[12];
    char stringdata7[6];
    char stringdata8[7];
    char stringdata9[8];
    char stringdata10[16];
    char stringdata11[15];
    char stringdata12[18];
    char stringdata13[9];
    char stringdata14[21];
    char stringdata15[11];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_VideoCallManager_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_VideoCallManager_t qt_meta_stringdata_VideoCallManager = {
    {
        QT_MOC_LITERAL(0, 16),  // "VideoCallManager"
        QT_MOC_LITERAL(17, 12),  // "keyGenerated"
        QT_MOC_LITERAL(30, 0),  // ""
        QT_MOC_LITERAL(31, 3),  // "key"
        QT_MOC_LITERAL(35, 11),  // "callStarted"
        QT_MOC_LITERAL(47, 16),  // "listeningStarted"
        QT_MOC_LITERAL(64, 11),  // "callStopped"
        QT_MOC_LITERAL(76, 5),  // "error"
        QT_MOC_LITERAL(82, 6),  // "output"
        QT_MOC_LITERAL(89, 7),  // "message"
        QT_MOC_LITERAL(97, 15),  // "onProcessOutput"
        QT_MOC_LITERAL(113, 14),  // "onProcessError"
        QT_MOC_LITERAL(128, 17),  // "onProcessFinished"
        QT_MOC_LITERAL(146, 8),  // "exitCode"
        QT_MOC_LITERAL(155, 20),  // "QProcess::ExitStatus"
        QT_MOC_LITERAL(176, 10)   // "exitStatus"
    },
    "VideoCallManager",
    "keyGenerated",
    "",
    "key",
    "callStarted",
    "listeningStarted",
    "callStopped",
    "error",
    "output",
    "message",
    "onProcessOutput",
    "onProcessError",
    "onProcessFinished",
    "exitCode",
    "QProcess::ExitStatus",
    "exitStatus"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_VideoCallManager[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
       9,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       6,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,   68,    2, 0x06,    1 /* Public */,
       4,    0,   71,    2, 0x06,    3 /* Public */,
       5,    0,   72,    2, 0x06,    4 /* Public */,
       6,    0,   73,    2, 0x06,    5 /* Public */,
       7,    1,   74,    2, 0x06,    6 /* Public */,
       8,    1,   77,    2, 0x06,    8 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
      10,    0,   80,    2, 0x08,   10 /* Private */,
      11,    0,   81,    2, 0x08,   11 /* Private */,
      12,    2,   82,    2, 0x08,   12 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    7,
    QMetaType::Void, QMetaType::QString,    9,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int, 0x80000000 | 14,   13,   15,

       0        // eod
};

Q_CONSTINIT const QMetaObject VideoCallManager::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_VideoCallManager.offsetsAndSizes,
    qt_meta_data_VideoCallManager,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_VideoCallManager_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<VideoCallManager, std::true_type>,
        // method 'keyGenerated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'callStarted'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'listeningStarted'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'callStopped'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'error'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'output'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'onProcessOutput'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onProcessError'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onProcessFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        QtPrivate::TypeAndForceComplete<QProcess::ExitStatus, std::false_type>
    >,
    nullptr
} };

void VideoCallManager::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<VideoCallManager *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->keyGenerated((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 1: _t->callStarted(); break;
        case 2: _t->listeningStarted(); break;
        case 3: _t->callStopped(); break;
        case 4: _t->error((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 5: _t->output((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 6: _t->onProcessOutput(); break;
        case 7: _t->onProcessError(); break;
        case 8: _t->onProcessFinished((*reinterpret_cast< std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QProcess::ExitStatus>>(_a[2]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (VideoCallManager::*)(const QString & );
            if (_t _q_method = &VideoCallManager::keyGenerated; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (VideoCallManager::*)();
            if (_t _q_method = &VideoCallManager::callStarted; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (VideoCallManager::*)();
            if (_t _q_method = &VideoCallManager::listeningStarted; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (VideoCallManager::*)();
            if (_t _q_method = &VideoCallManager::callStopped; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (VideoCallManager::*)(const QString & );
            if (_t _q_method = &VideoCallManager::error; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (VideoCallManager::*)(const QString & );
            if (_t _q_method = &VideoCallManager::output; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 5;
                return;
            }
        }
    }
}

const QMetaObject *VideoCallManager::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *VideoCallManager::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_VideoCallManager.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int VideoCallManager::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 9)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 9;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 9)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 9;
    }
    return _id;
}

// SIGNAL 0
void VideoCallManager::keyGenerated(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void VideoCallManager::callStarted()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void VideoCallManager::listeningStarted()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}

// SIGNAL 3
void VideoCallManager::callStopped()
{
    QMetaObject::activate(this, &staticMetaObject, 3, nullptr);
}

// SIGNAL 4
void VideoCallManager::error(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}

// SIGNAL 5
void VideoCallManager::output(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 5, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
