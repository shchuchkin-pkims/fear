#include "qrshowdialog.h"

#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPainter>
#include <QPushButton>
#include <QScreen>
#include <QStandardPaths>
#include <QVBoxLayout>

#include <qrencode.h>

namespace {

constexpr int  CELL_PIXELS   = 8;       // each QR module → CELL_PIXELS x CELL_PIXELS
constexpr int  QUIET_MODULES = 4;       // standard quiet zone
constexpr int  MIN_DIALOG_W  = 360;

/**
 * Render a libqrencode QRcode to an upscaled, quiet-zoned QImage.
 * Returns a null QImage if `qr` is null.
 */
QImage renderQrToImage(const QRcode *qr) {
    if (!qr) return QImage();

    const int modules = qr->width;                          // QR side in modules
    const int sideMod = modules + 2 * QUIET_MODULES;        // include quiet zone
    const int sidePx  = sideMod * CELL_PIXELS;

    QImage img(sidePx, sidePx, QImage::Format_RGB888);
    img.fill(Qt::white);

    QPainter p(&img);
    p.setPen(Qt::NoPen);
    p.setBrush(Qt::black);

    for (int y = 0; y < modules; ++y) {
        for (int x = 0; x < modules; ++x) {
            // bit 0 of qr->data[y*width + x] = "is dark"
            if (qr->data[y * modules + x] & 1) {
                p.drawRect((QUIET_MODULES + x) * CELL_PIXELS,
                           (QUIET_MODULES + y) * CELL_PIXELS,
                           CELL_PIXELS, CELL_PIXELS);
            }
        }
    }
    return img;
}

}  // namespace

// ===== Static factories =====

QrShowDialog *QrShowDialog::fromText(const QString &text,
                                     const QString &title,
                                     const QString &subtitle,
                                     QWidget *parent) {
    QByteArray utf8 = text.toUtf8();
    QRcode *qr = QRcode_encodeData(utf8.size(),
                                   reinterpret_cast<const unsigned char *>(utf8.constData()),
                                   /*version=*/0,        // auto
                                   QR_ECLEVEL_M);
    if (!qr) return nullptr;
    QImage img = renderQrToImage(qr);
    QRcode_free(qr);
    if (img.isNull()) return nullptr;
    return new QrShowDialog(img, title, subtitle, parent);
}

QrShowDialog *QrShowDialog::fromBinary(const QByteArray &bytes,
                                       const QString &title,
                                       const QString &subtitle,
                                       QWidget *parent) {
    return fromText(QString::fromLatin1(bytes.toBase64()), title, subtitle, parent);
}

// ===== Instance =====

QrShowDialog::QrShowDialog(const QImage &qr, const QString &title,
                           const QString &subtitle, QWidget *parent)
    : QDialog(parent), m_qrImage(qr), m_title(title)
{
    setWindowTitle(title);
    setModal(true);

    // Cap the displayed pixmap at half the screen height so the dialog stays usable
    int displayPx = qr.width();
    if (parent) {
        int cap = parent->screen() ? parent->screen()->geometry().height() / 2 : 600;
        if (displayPx > cap) displayPx = cap;
    }

    auto *layout = new QVBoxLayout(this);

    if (!subtitle.isEmpty()) {
        auto *sub = new QLabel(subtitle, this);
        sub->setWordWrap(true);
        sub->setStyleSheet("color: gray;");
        layout->addWidget(sub);
    }

    m_label = new QLabel(this);
    m_label->setAlignment(Qt::AlignCenter);
    m_label->setPixmap(QPixmap::fromImage(qr).scaled(displayPx, displayPx,
                                                     Qt::KeepAspectRatio,
                                                     Qt::FastTransformation));
    layout->addWidget(m_label, /*stretch=*/1, Qt::AlignCenter);

    auto *btnRow = new QHBoxLayout;
    auto *saveBtn  = new QPushButton(tr("Save as PNG…"), this);
    auto *closeBtn = new QPushButton(tr("Close"),       this);
    closeBtn->setDefault(true);
    btnRow->addStretch(1);
    btnRow->addWidget(saveBtn);
    btnRow->addWidget(closeBtn);
    layout->addLayout(btnRow);

    setMinimumWidth(qMax(MIN_DIALOG_W, displayPx + 40));

    connect(saveBtn,  &QPushButton::clicked, this, &QrShowDialog::saveAsPng);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
}

void QrShowDialog::saveAsPng() {
    const QString defaultDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    const QString suggested  = defaultDir + "/" + m_title.toLower().replace(' ', '_') + ".png";
    QString path = QFileDialog::getSaveFileName(this, tr("Save QR as PNG"),
                                                suggested, tr("PNG image (*.png)"));
    if (path.isEmpty()) return;
    if (!path.endsWith(".png", Qt::CaseInsensitive)) path += ".png";
    if (!m_qrImage.save(path, "PNG")) {
        QMessageBox::warning(this, tr("Save failed"),
                             tr("Could not write %1").arg(path));
    }
}
