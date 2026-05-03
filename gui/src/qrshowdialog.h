#ifndef FEAR_QR_SHOW_DIALOG_H
#define FEAR_QR_SHOW_DIALOG_H

#include <QDialog>
#include <QImage>
#include <QString>

class QLabel;

/**
 * Renders a binary blob (typically the encrypted identity backup, see
 * identity/identity_backup.h) as a QR code so the user can scan it with
 * another device.
 *
 * Two construction paths:
 *  - `fromText(...)`         — encode arbitrary UTF-8 text
 *  - `fromBinary(...)`       — encode binary by base64-encoding first
 *
 * Both produce a square QR PNG that the user can save to disk.
 */
class QrShowDialog : public QDialog {
    Q_OBJECT
public:
    /** Build a dialog for arbitrary text. Returns nullptr on encode failure. */
    static QrShowDialog *fromText(const QString &text,
                                  const QString &title,
                                  const QString &subtitle,
                                  QWidget *parent = nullptr);

    /** Build for binary content (base64-encoded first). */
    static QrShowDialog *fromBinary(const QByteArray &bytes,
                                    const QString &title,
                                    const QString &subtitle,
                                    QWidget *parent = nullptr);

private slots:
    void saveAsPng();

private:
    QrShowDialog(const QImage &qr, const QString &title,
                 const QString &subtitle, QWidget *parent);

    QImage  m_qrImage;        // the rendered QR (RGB888, scaled)
    QLabel *m_label;
    QString m_title;
};

#endif
