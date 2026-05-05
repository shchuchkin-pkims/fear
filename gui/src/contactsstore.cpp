#include "contactsstore.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>

namespace fear {

ContactsStore *ContactsStore::instance() {
    static ContactsStore inst;
    return &inst;
}

ContactsStore::ContactsStore(QObject *parent) : QObject(parent) {
    reload();
}

QString ContactsStore::filePath() const {
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    if (dir.isEmpty()) dir = QDir::homePath() + "/.config/fear";
    QDir().mkpath(dir);
    return dir + "/contacts_cache.json";
}

QVector<ContactsStore::Record> ContactsStore::reload() {
    m_cache.clear();
    QFile f(filePath());
    if (!f.open(QIODevice::ReadOnly)) return m_cache;
    const auto doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isObject()) return m_cache;
    const QJsonArray arr = doc.object().value("contacts").toArray();
    for (const auto &v : arr) {
        const auto o = v.toObject();
        Record r;
        r.name     = o.value("name").toString();
        r.handle   = o.value("handle").toString();
        r.server   = o.value("server").toString();
        r.pk       = o.value("pk").toString();
        r.verified = o.value("verified").toBool();
        if (!r.pk.isEmpty()) m_cache.append(r);
    }
    return m_cache;
}

void ContactsStore::replaceAll(const QVector<Record> &records) {
    m_cache = records;
    QJsonArray arr;
    for (const auto &r : records) {
        QJsonObject o;
        o["name"]     = r.name;
        o["handle"]   = r.handle;
        o["server"]   = r.server;
        o["pk"]       = r.pk;
        o["verified"] = r.verified;
        arr.append(o);
    }
    QJsonObject root;
    root["contacts"] = arr;
    QFile f(filePath());
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(QJsonDocument(root).toJson(QJsonDocument::Compact));
    }
    emit contactsChanged();
}

}  // namespace fear
