#ifndef FEAR_CONNECTIONDIALOG_H
#define FEAR_CONNECTIONDIALOG_H

#include <QDialog>
#include "backend.h"

class QLineEdit;
class QPushButton;
class QPlainTextEdit;
class QLabel;
class QComboBox;
class QTimer;

namespace fear {

class ProfileSettings;

class ConnectionDialog : public QDialog {
    Q_OBJECT
public:
    /** `profile` and `identityPath` are required for registration-state
     *  detection: the dialog issues a fast LOOKUP_HANDLE_BY_PK whenever
     *  the server selection changes and toggles Connect/Register
     *  accordingly. Both pointers must remain valid for the dialog's
     *  lifetime — they are owned by the host window. */
    ConnectionDialog(ProfileSettings *profile,
                     const QString   &identityPath,
                     QWidget         *parent = nullptr);

    Backend::ConnectMode mode() const { return m_mode; }
    QString host() const;
    int     port() const;
    QString room() const;
    QString name() const;
    QString key()  const;

    void loadFromSettings();
    void saveToSettings() const;

private slots:
    void onRegisterClicked();
    void onHostChanged();

private:
    enum RegStatus { RegUnknown, RegYes, RegNo, RegProbing, RegError };

    void setMode(Backend::ConnectMode m);
    void updateModeUi();
    void setRegistrationStatus(RegStatus st, const QString &handle = QString());
    void scheduleRegistrationProbe();
    void runRegistrationProbe();
    void refreshButtons();

    Backend::ConnectMode m_mode = Backend::CREATE_ROOM;

    ProfileSettings *m_profile;
    QString          m_identityPath;
    RegStatus        m_regStatus = RegUnknown;
    QString          m_currentHandle;
    QTimer          *m_probeDebounce;
    /** Monotonic counter used to discard stale lookup replies after the
     *  user has typed further into the host field. */
    quint64          m_probeSeq = 0;

    QPushButton *m_createBtn;
    QPushButton *m_joinBtn;
    QPushButton *m_manualBtn;

    QComboBox *m_host;
    QLineEdit *m_port;
    QLineEdit *m_room;
    QLineEdit *m_name;
    QPlainTextEdit *m_key;
    QLabel    *m_keyLabel;

    QLabel      *m_statusLabel;
    QPushButton *m_connectBtn;
    QPushButton *m_registerBtn;
    QPushButton *m_cancelBtn;
};

}

#endif
