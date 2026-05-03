#ifndef FEAR_PROFILE_DIALOG_H
#define FEAR_PROFILE_DIALOG_H

#include <QDialog>

class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;

namespace fear {

class ProfileSettings;

/**
 * "My Profile" — Qt counterpart of Android ProfileScreen.
 *
 * Shows a monogram avatar, the user's display name (editable in-place),
 * the list of `@name@server` handles claimed locally, the cryptographic
 * fingerprint, and shortcuts to export the identity / show it as a QR.
 *
 * Uses ProfileSettings for display-name + registered-servers persistence
 * and reads identity_pk from the on-disk identity file (`identityPath`).
 *
 * `onExport` / `onShowQr` are simple closures the caller wires to the
 * existing IdentityBackupDialog flow in ChatWindow.
 */
class ProfileDialog : public QDialog {
    Q_OBJECT
public:
    ProfileDialog(ProfileSettings *settings,
                  const QString &identityPath,
                  std::function<void()> onExport,
                  std::function<void()> onShowQr,
                  QWidget *parent = nullptr);

private slots:
    void saveDisplayName();
    void copyToClipboard(const QString &text);

private:
    ProfileSettings *m_settings;
    QString          m_identityPath;
    std::function<void()> m_onExport;
    std::function<void()> m_onShowQr;

    QLabel      *m_avatar;
    QLineEdit   *m_nameEdit;
    QPushButton *m_saveBtn;
    QLabel      *m_shortIdLabel;
    QListWidget *m_handlesList;
    QLabel      *m_fpLabel;

    void rebuildIdentityLabels();
};

}  // namespace fear

#endif
