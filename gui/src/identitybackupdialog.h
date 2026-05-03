#ifndef FEAR_IDENTITY_BACKUP_DIALOG_H
#define FEAR_IDENTITY_BACKUP_DIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>

/**
 * Modal dialog for exporting / importing the Ed25519 identity to an
 * encrypted .fbk file (Argon2id + XSalsa20-Poly1305, see
 * identity/identity_backup.h).
 *
 * Two modes selected by `mode`:
 *   - Export: read identity from `identityPath`, ask password (twice),
 *             write encrypted blob to a user-chosen .fbk file.
 *   - Import: ask password, read user-chosen .fbk file, decrypt,
 *             overwrite `identityPath` with the recovered keypair.
 *
 * The dialog handles all libsodium calls itself; caller only supplies
 * the path of the live identity file and (for import) is responsible
 * for re-loading any in-memory identity caches after acceptance.
 */
class IdentityBackupDialog : public QDialog {
    Q_OBJECT
public:
    enum Mode { Export, Import };

    IdentityBackupDialog(Mode mode, const QString &identityPath, QWidget *parent = nullptr);

private slots:
    void browseFile();
    void onAccept();

private:
    Mode m_mode;
    QString m_identityPath;
    QString m_filePath;

    QLabel     *m_pathLabel;
    QPushButton *m_browseBtn;
    QLineEdit  *m_password;
    QLineEdit  *m_passwordConfirm;
    QLabel     *m_status;
    QPushButton *m_okBtn;

    bool runExport(QString *err);
    bool runImport(QString *err);
};

#endif
