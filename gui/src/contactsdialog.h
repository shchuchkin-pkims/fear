#ifndef FEAR_CONTACTS_DIALOG_H
#define FEAR_CONTACTS_DIALOG_H

#include <QDialog>

class QLabel;
class QListWidget;
class QListWidgetItem;
class QPushButton;

namespace fear {

/**
 * Desktop counterpart of the Android ContactsScreen — phase B-3 minimum
 * cross-device test surface. Shows the contact list as decoded from the
 * server's encrypted blob (BLOB_GET → decrypt with K_contacts derived
 * from identity_sk → parse JSON).
 *
 * Phase B-3 desktop is read-mostly: 'Refresh from server' pulls the blob,
 * 'Add contact…' resolves a `nickname@server` and pushes back. The intent
 * is parity with phone for verification; full UX integration with the
 * chat list is Phase B-5.
 */
class ContactsDialog : public QDialog {
    Q_OBJECT
public:
    ContactsDialog(const QString &identityPath,
                   const QString &serverHost,
                   uint16_t       serverPort,
                   QWidget       *parent = nullptr);

signals:
    /** Emitted when the user wants to open a DM with `dmRoomId` ("dm:..."). */
    void openDmRequested(const QString &dmRoomId);

private slots:
    void refreshFromServer();
    void addContact();
    void onContactActivated(QListWidgetItem *item);

private:
    QString  m_identityPath;
    QString  m_serverHost;
    uint16_t m_serverPort;

    QLabel      *m_status;
    QListWidget *m_list;
    QPushButton *m_refreshBtn;
    QPushButton *m_addBtn;

    /** Replace the on-screen list with `json` (output of contacts_cipher_decrypt). */
    void renderJson(const QString &json);
};

}  // namespace fear

#endif
