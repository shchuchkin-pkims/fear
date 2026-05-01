#include "theme.h"

#include <QFile>
#include <QTextStream>
#include <QApplication>
#include <QCryptographicHash>

namespace fear {

Theme& Theme::instance() {
    static Theme t;
    return t;
}

Theme::Theme(QObject *parent) : QObject(parent) {}

void Theme::setMode(Mode m) {
    if (m == m_mode) return;
    m_mode = m;
    if (auto *app = qobject_cast<QApplication*>(QApplication::instance())) {
        app->setStyleSheet(styleSheet());
    }
    emit modeChanged(m);
}

QString Theme::styleSheet() const {
    const QString path = (m_mode == Dark) ? ":/theme/dark.qss" : ":/theme/light.qss";
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return {};
    return QString::fromUtf8(f.readAll());
}

QColor Theme::accent() const          { return m_mode == Dark ? QColor("#5288C1") : QColor("#2AABEE"); }
QColor Theme::background() const      { return m_mode == Dark ? QColor("#2A2C30") : QColor("#FFFFFF"); }
QColor Theme::sidebarBackground() const { return m_mode == Dark ? QColor("#2A2C30") : QColor("#FFFFFF"); }
QColor Theme::chatBackground() const  { return m_mode == Dark ? QColor("#1B1D20") : QColor("#E6EBEE"); }
QColor Theme::surfaceHover() const    { return m_mode == Dark ? QColor("#34373B") : QColor("#F4F4F5"); }
QColor Theme::selectedItem() const    { return m_mode == Dark ? QColor("#2B5278") : QColor("#2AABEE"); }
QColor Theme::textPrimary() const     { return m_mode == Dark ? QColor("#FFFFFF") : QColor("#000000"); }
QColor Theme::textSecondary() const   { return m_mode == Dark ? QColor("#8A8D92") : QColor("#707579"); }
QColor Theme::border() const          { return m_mode == Dark ? QColor("#1A1C1E") : QColor("#DADCE0"); }
QColor Theme::bubbleSelf() const      { return m_mode == Dark ? QColor("#2B5278") : QColor("#EFFDDE"); }
QColor Theme::bubblePeer() const      { return m_mode == Dark ? QColor("#3A3D42") : QColor("#FFFFFF"); }
QColor Theme::bubbleSelfText() const  { return m_mode == Dark ? QColor("#FFFFFF") : QColor("#000000"); }
QColor Theme::bubblePeerText() const  { return m_mode == Dark ? QColor("#FFFFFF") : QColor("#000000"); }
QColor Theme::unreadBadge() const     { return m_mode == Dark ? QColor("#5288C1") : QColor("#4DCD5E"); }

QColor Theme::avatarColor(const QString &seed) const {
    static const QColor palette[] = {
        QColor("#E17076"), QColor("#EDA86C"), QColor("#A695E7"),
        QColor("#7BC862"), QColor("#65AADD"), QColor("#EE7AAE"),
        QColor("#6EC9CB"), QColor("#FAA774")
    };
    if (seed.isEmpty()) return palette[0];
    QByteArray h = QCryptographicHash::hash(seed.toUtf8(), QCryptographicHash::Md5);
    return palette[static_cast<unsigned char>(h.at(0)) % (sizeof(palette)/sizeof(palette[0]))];
}

}
