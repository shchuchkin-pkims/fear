/****************************************************************************
** Meta object code from reading C++ file 'backend.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.4.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../backend.h"
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'backend.h' doesn't include <QObject>."
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
struct qt_meta_stringdata_Backend_t {
    uint offsetsAndSizes[46];
    char stringdata0[8];
    char stringdata1[10];
    char stringdata2[1];
    char stringdata3[13];
    char stringdata4[14];
    char stringdata5[13];
    char stringdata6[4];
    char stringdata7[16];
    char stringdata8[9];
    char stringdata9[12];
    char stringdata10[9];
    char stringdata11[6];
    char stringdata12[18];
    char stringdata13[12];
    char stringdata14[15];
    char stringdata15[15];
    char stringdata16[17];
    char stringdata17[9];
    char stringdata18[21];
    char stringdata19[7];
    char stringdata20[15];
    char stringdata21[15];
    char stringdata22[17];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_Backend_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_Backend_t qt_meta_stringdata_Backend = {
    {
        QT_MOC_LITERAL(0, 7),  // "Backend"
        QT_MOC_LITERAL(8, 9),  // "connected"
        QT_MOC_LITERAL(18, 0),  // ""
        QT_MOC_LITERAL(19, 12),  // "disconnected"
        QT_MOC_LITERAL(32, 13),  // "serverCreated"
        QT_MOC_LITERAL(46, 12),  // "keyGenerated"
        QT_MOC_LITERAL(59, 3),  // "key"
        QT_MOC_LITERAL(63, 15),  // "contactsUpdated"
        QT_MOC_LITERAL(79, 8),  // "contacts"
        QT_MOC_LITERAL(88, 11),  // "newMessages"
        QT_MOC_LITERAL(100, 8),  // "messages"
        QT_MOC_LITERAL(109, 5),  // "error"
        QT_MOC_LITERAL(115, 17),  // "identityGenerated"
        QT_MOC_LITERAL(133, 11),  // "fingerprint"
        QT_MOC_LITERAL(145, 14),  // "onClientStdout"
        QT_MOC_LITERAL(160, 14),  // "onClientStderr"
        QT_MOC_LITERAL(175, 16),  // "onClientFinished"
        QT_MOC_LITERAL(192, 8),  // "exitCode"
        QT_MOC_LITERAL(201, 20),  // "QProcess::ExitStatus"
        QT_MOC_LITERAL(222, 6),  // "status"
        QT_MOC_LITERAL(229, 14),  // "onServerStdout"
        QT_MOC_LITERAL(244, 14),  // "onServerStderr"
        QT_MOC_LITERAL(259, 16)   // "onServerFinished"
    },
    "Backend",
    "connected",
    "",
    "disconnected",
    "serverCreated",
    "keyGenerated",
    "key",
    "contactsUpdated",
    "contacts",
    "newMessages",
    "messages",
    "error",
    "identityGenerated",
    "fingerprint",
    "onClientStdout",
    "onClientStderr",
    "onClientFinished",
    "exitCode",
    "QProcess::ExitStatus",
    "status",
    "onServerStdout",
    "onServerStderr",
    "onServerFinished"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_Backend[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
      14,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       8,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,   98,    2, 0x06,    1 /* Public */,
       3,    0,   99,    2, 0x06,    2 /* Public */,
       4,    0,  100,    2, 0x06,    3 /* Public */,
       5,    1,  101,    2, 0x06,    4 /* Public */,
       7,    1,  104,    2, 0x06,    6 /* Public */,
       9,    1,  107,    2, 0x06,    8 /* Public */,
      11,    1,  110,    2, 0x06,   10 /* Public */,
      12,    1,  113,    2, 0x06,   12 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
      14,    0,  116,    2, 0x08,   14 /* Private */,
      15,    0,  117,    2, 0x08,   15 /* Private */,
      16,    2,  118,    2, 0x08,   16 /* Private */,
      20,    0,  123,    2, 0x08,   19 /* Private */,
      21,    0,  124,    2, 0x08,   20 /* Private */,
      22,    2,  125,    2, 0x08,   21 /* Private */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    6,
    QMetaType::Void, QMetaType::QStringList,    8,
    QMetaType::Void, QMetaType::QStringList,   10,
    QMetaType::Void, QMetaType::QString,   11,
    QMetaType::Void, QMetaType::QString,   13,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int, 0x80000000 | 18,   17,   19,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int, 0x80000000 | 18,   17,   19,

       0        // eod
};

Q_CONSTINIT const QMetaObject Backend::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_Backend.offsetsAndSizes,
    qt_meta_data_Backend,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_Backend_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<Backend, std::true_type>,
        // method 'connected'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'disconnected'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'serverCreated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'keyGenerated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'contactsUpdated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QStringList &, std::false_type>,
        // method 'newMessages'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QStringList &, std::false_type>,
        // method 'error'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'identityGenerated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'onClientStdout'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onClientStderr'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onClientFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        QtPrivate::TypeAndForceComplete<QProcess::ExitStatus, std::false_type>,
        // method 'onServerStdout'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onServerStderr'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onServerFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        QtPrivate::TypeAndForceComplete<QProcess::ExitStatus, std::false_type>
    >,
    nullptr
} };

void Backend::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Backend *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->connected(); break;
        case 1: _t->disconnected(); break;
        case 2: _t->serverCreated(); break;
        case 3: _t->keyGenerated((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 4: _t->contactsUpdated((*reinterpret_cast< std::add_pointer_t<QStringList>>(_a[1]))); break;
        case 5: _t->newMessages((*reinterpret_cast< std::add_pointer_t<QStringList>>(_a[1]))); break;
        case 6: _t->error((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 7: _t->identityGenerated((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 8: _t->onClientStdout(); break;
        case 9: _t->onClientStderr(); break;
        case 10: _t->onClientFinished((*reinterpret_cast< std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QProcess::ExitStatus>>(_a[2]))); break;
        case 11: _t->onServerStdout(); break;
        case 12: _t->onServerStderr(); break;
        case 13: _t->onServerFinished((*reinterpret_cast< std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QProcess::ExitStatus>>(_a[2]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (Backend::*)();
            if (_t _q_method = &Backend::connected; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (Backend::*)();
            if (_t _q_method = &Backend::disconnected; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (Backend::*)();
            if (_t _q_method = &Backend::serverCreated; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (Backend::*)(const QString & );
            if (_t _q_method = &Backend::keyGenerated; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (Backend::*)(const QStringList & );
            if (_t _q_method = &Backend::contactsUpdated; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (Backend::*)(const QStringList & );
            if (_t _q_method = &Backend::newMessages; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (Backend::*)(const QString & );
            if (_t _q_method = &Backend::error; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (Backend::*)(const QString & );
            if (_t _q_method = &Backend::identityGenerated; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 7;
                return;
            }
        }
    }
}

const QMetaObject *Backend::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Backend::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Backend.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int Backend::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 14)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 14;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 14)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 14;
    }
    return _id;
}

// SIGNAL 0
void Backend::connected()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void Backend::disconnected()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void Backend::serverCreated()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}

// SIGNAL 3
void Backend::keyGenerated(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}

// SIGNAL 4
void Backend::contactsUpdated(const QStringList & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}

// SIGNAL 5
void Backend::newMessages(const QStringList & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 5, _a);
}

// SIGNAL 6
void Backend::error(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 6, _a);
}

// SIGNAL 7
void Backend::identityGenerated(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 7, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
