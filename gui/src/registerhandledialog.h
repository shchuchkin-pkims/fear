#ifndef FEAR_REGISTER_HANDLE_DIALOG_H
#define FEAR_REGISTER_HANDLE_DIALOG_H

#include <QDialog>
#include <QString>

class QLineEdit;
class QPushButton;
class QLabel;

namespace fear {

/**
 * Modal dialog that asks the user to choose a handle (`@nickname`) and
 * synchronously registers it on the relay over the wire-protocol command
 * MSG_TYPE_REGISTER_HANDLE. On success, the chosen handle is returned via
 * `chosenHandle()` and the dialog accepts; on conflict / network failure,
 * an inline error is shown and the user can retry.
 *
 * The actual server round-trip is launched in a worker thread so the UI
 * does not freeze while we wait. Identity public/secret keys are loaded
 * from `identityPath` at submit time — the dialog itself never holds them.
 */
class RegisterHandleDialog : public QDialog {
    Q_OBJECT
public:
    RegisterHandleDialog(const QString &serverHost,
                         uint16_t       serverPort,
                         const QString &identityPath,
                         const QString &suggestedHandle,
                         QWidget       *parent = nullptr);

    /** The handle that was successfully registered (lowercase, no «@»). */
    QString chosenHandle() const { return m_chosen; }

private slots:
    void onSubmitClicked();

private:
    void setBusy(bool busy);
    void showError(const QString &msg);
    void runRegister(const QString &handle);

    QString m_host;
    uint16_t m_port;
    QString m_identityPath;
    QString m_chosen;

    QLabel      *m_intro;
    QLineEdit   *m_handleEdit;
    QLabel      *m_errorLbl;
    QPushButton *m_submitBtn;
    QPushButton *m_cancelBtn;
};

}  // namespace fear

#endif
