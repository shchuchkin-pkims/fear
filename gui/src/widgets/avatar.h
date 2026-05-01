#ifndef FEAR_AVATAR_H
#define FEAR_AVATAR_H

#include <QWidget>
#include <QString>

namespace fear {

class Avatar : public QWidget {
    Q_OBJECT
public:
    explicit Avatar(QWidget *parent = nullptr);

    void setSeed(const QString &seed);
    void setInitials(const QString &initials);
    void setDiameter(int px);

    QSize sizeHint() const override { return QSize(m_diameter, m_diameter); }

protected:
    void paintEvent(QPaintEvent *) override;

private:
    QString m_seed;
    QString m_initials;
    int m_diameter = 42;
};

}

#endif
