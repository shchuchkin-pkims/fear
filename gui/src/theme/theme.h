#ifndef FEAR_THEME_H
#define FEAR_THEME_H

#include <QObject>
#include <QColor>
#include <QString>

namespace fear {

class Theme : public QObject {
    Q_OBJECT
public:
    enum Mode { Dark, Light };

    static Theme& instance();

    Mode mode() const { return m_mode; }
    void setMode(Mode m);

    QString styleSheet() const;

    QColor accent() const;
    QColor background() const;
    QColor sidebarBackground() const;
    QColor chatBackground() const;
    QColor surfaceHover() const;
    QColor selectedItem() const;
    QColor textPrimary() const;
    QColor textSecondary() const;
    QColor border() const;
    QColor bubbleSelf() const;
    QColor bubblePeer() const;
    QColor bubbleSelfText() const;
    QColor bubblePeerText() const;
    QColor unreadBadge() const;

    QColor avatarColor(const QString &seed) const;

signals:
    void modeChanged(Mode);

private:
    explicit Theme(QObject *parent = nullptr);
    Mode m_mode = Dark;
};

}

#endif
