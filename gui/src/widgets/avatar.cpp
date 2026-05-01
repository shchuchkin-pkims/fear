#include "avatar.h"
#include "../theme/theme.h"

#include <QPainter>
#include <QFontMetrics>
#include <QRegularExpression>

namespace fear {

Avatar::Avatar(QWidget *parent) : QWidget(parent) {
    setFixedSize(m_diameter, m_diameter);
    setAttribute(Qt::WA_TranslucentBackground);
}

void Avatar::setSeed(const QString &seed) {
    if (seed == m_seed) return;
    m_seed = seed;
    if (m_initials.isEmpty() && !seed.isEmpty()) {
        const QStringList parts = seed.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        QString s;
        if (parts.size() >= 2) {
            s = QString(parts[0].at(0)) + QString(parts[1].at(0));
        } else if (!seed.isEmpty()) {
            s = seed.left(2);
        }
        m_initials = s.toUpper();
    }
    update();
}

void Avatar::setInitials(const QString &initials) {
    m_initials = initials.toUpper();
    update();
}

void Avatar::setDiameter(int px) {
    m_diameter = px;
    setFixedSize(px, px);
    update();
}

void Avatar::paintEvent(QPaintEvent *) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    const QColor c = Theme::instance().avatarColor(m_seed);
    p.setBrush(c);
    p.setPen(Qt::NoPen);
    p.drawEllipse(rect());

    if (!m_initials.isEmpty()) {
        QFont f = font();
        f.setPixelSize(qMax(10, m_diameter / 2));
        f.setWeight(QFont::DemiBold);
        p.setFont(f);
        p.setPen(QColor(255, 255, 255));
        p.drawText(rect(), Qt::AlignCenter, m_initials);
    }
}

}
