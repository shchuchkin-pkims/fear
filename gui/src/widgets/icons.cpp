#include "icons.h"

#include <QPainter>
#include <QPainterPath>
#include <QPixmap>

namespace fear {
namespace {

/* Рисуем в квадрате 24x24 и масштабируем: так одна и та же форма одинаково
 * выглядит и в шапке, и в списке, и не приходится подбирать координаты под
 * каждый размер. */
constexpr qreal kBase = 24.0;

void strokePen(QPainter &p, const QColor &c, qreal width) {
    QPen pen(c, width);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);
}

void paintPhone(QPainter &p, const QColor &c) {
    strokePen(p, c, 1.9);
    QPainterPath path;
    /* Трубка: короткая дуга у уха, длинная у микрофона и перемычка между. */
    path.moveTo(7.5, 4.5);
    path.cubicTo(5.0, 6.0, 4.5, 9.0, 6.0, 12.0);
    path.cubicTo(7.5, 15.0, 10.0, 17.5, 13.0, 18.5);
    path.cubicTo(16.0, 19.5, 18.5, 19.0, 19.8, 16.8);
    p.drawPath(path);
    p.setBrush(c);
    p.setPen(Qt::NoPen);
    p.drawEllipse(QPointF(6.6, 5.2), 2.1, 2.1);
    p.drawEllipse(QPointF(18.6, 17.6), 2.1, 2.1);
}

void paintVideo(QPainter &p, const QColor &c) {
    p.setPen(Qt::NoPen);
    p.setBrush(c);
    /* Корпус камеры и «объектив» сбоку - тот же силуэт, что на телефоне. */
    p.drawRoundedRect(QRectF(3.0, 7.0, 12.5, 10.0), 2.5, 2.5);
    QPainterPath lens;
    lens.moveTo(17.0, 10.0);
    lens.lineTo(21.0, 7.5);
    lens.lineTo(21.0, 16.5);
    lens.lineTo(17.0, 14.0);
    lens.closeSubpath();
    p.drawPath(lens);
}

void paintMore(QPainter &p, const QColor &c) {
    p.setPen(Qt::NoPen);
    p.setBrush(c);
    for (int i = 0; i < 3; i++) {
        p.drawEllipse(QPointF(12.0, 6.0 + i * 6.0), 1.7, 1.7);
    }
}

void paintAttach(QPainter &p, const QColor &c) {
    strokePen(p, c, 1.9);
    QPainterPath path;
    /* Скрепка: длинная дуга вниз, разворот и короткий подъём. */
    path.moveTo(16.5, 7.0);
    path.lineTo(8.5, 15.0);
    path.cubicTo(6.8, 16.7, 6.8, 19.0, 8.5, 20.2);
    path.cubicTo(10.2, 21.4, 12.4, 21.0, 13.8, 19.6);
    path.lineTo(19.5, 13.9);
    path.cubicTo(21.6, 11.8, 21.6, 8.4, 19.5, 6.3);
    path.cubicTo(17.4, 4.2, 14.0, 4.2, 11.9, 6.3);
    path.lineTo(5.6, 12.6);
    p.drawPath(path);
}

void paintSend(QPainter &p, const QColor &c) {
    p.setPen(Qt::NoPen);
    p.setBrush(c);
    /* Бумажный самолётик, как в мессенджерах: треугольник с выемкой сзади. */
    QPainterPath path;
    path.moveTo(3.0, 20.5);
    path.lineTo(21.5, 12.0);
    path.lineTo(3.0, 3.5);
    path.lineTo(6.2, 12.0);
    path.closeSubpath();
    p.drawPath(path);
}

void paintMenu(QPainter &p, const QColor &c) {
    strokePen(p, c, 2.0);
    for (int i = 0; i < 3; i++) {
        const qreal y = 7.0 + i * 5.0;
        p.drawLine(QPointF(4.5, y), QPointF(19.5, y));
    }
}

void paintPlus(QPainter &p, const QColor &c) {
    strokePen(p, c, 2.2);
    p.drawLine(QPointF(12.0, 5.5), QPointF(12.0, 18.5));
    p.drawLine(QPointF(5.5, 12.0), QPointF(18.5, 12.0));
}

void paintSearch(QPainter &p, const QColor &c) {
    strokePen(p, c, 1.9);
    p.drawEllipse(QPointF(10.5, 10.5), 5.5, 5.5);
    p.drawLine(QPointF(14.6, 14.6), QPointF(20.0, 20.0));
}

void paintSmile(QPainter &p, const QColor &c) {
    strokePen(p, c, 1.8);
    p.drawEllipse(QPointF(12.0, 12.0), 8.5, 8.5);
    QPainterPath mouth;
    mouth.moveTo(8.0, 13.6);
    mouth.cubicTo(9.6, 16.6, 14.4, 16.6, 16.0, 13.6);
    p.drawPath(mouth);
    p.setPen(Qt::NoPen);
    p.setBrush(c);
    p.drawEllipse(QPointF(9.3, 9.8), 1.15, 1.15);
    p.drawEllipse(QPointF(14.7, 9.8), 1.15, 1.15);
}

} // namespace

QIcon icon(Glyph g, const QColor &color, int px) {
    /* Рисуем сразу под нужный размер, а не масштабируем готовую картинку:
     * иначе тонкие линии на неудачном множителе размываются. */
    QPixmap pm(px, px);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.scale(px / kBase, px / kBase);

    switch (g) {
        case Glyph::Phone:  paintPhone(p, color);  break;
        case Glyph::Video:  paintVideo(p, color);  break;
        case Glyph::More:   paintMore(p, color);   break;
        case Glyph::Attach: paintAttach(p, color); break;
        case Glyph::Send:   paintSend(p, color);   break;
        case Glyph::Menu:   paintMenu(p, color);   break;
        case Glyph::Plus:   paintPlus(p, color);   break;
        case Glyph::Search: paintSearch(p, color); break;
        case Glyph::Smile:  paintSmile(p, color);  break;
    }
    p.end();
    return QIcon(pm);
}

} // namespace fear
