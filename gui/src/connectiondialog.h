#ifndef FEAR_CONNECTIONDIALOG_H
#define FEAR_CONNECTIONDIALOG_H

#include <QDialog>
#include "backend.h"

class QLineEdit;
class QPushButton;
class QPlainTextEdit;
class QLabel;
class QComboBox;

namespace fear {

class ConnectionDialog : public QDialog {
    Q_OBJECT
public:
    explicit ConnectionDialog(QWidget *parent = nullptr);

    Backend::ConnectMode mode() const { return m_mode; }
    QString host() const;
    int     port() const;
    QString room() const;
    QString name() const;
    QString key()  const;

    void loadFromSettings();
    void saveToSettings() const;

private:
    void setMode(Backend::ConnectMode m);
    void updateModeUi();

    Backend::ConnectMode m_mode = Backend::CREATE_ROOM;

    QPushButton *m_createBtn;
    QPushButton *m_joinBtn;
    QPushButton *m_manualBtn;

    QComboBox *m_host;
    QLineEdit *m_port;
    QLineEdit *m_room;
    QLineEdit *m_name;
    QPlainTextEdit *m_key;
    QLabel    *m_keyLabel;

    QPushButton *m_connectBtn;
    QPushButton *m_cancelBtn;
};

}

#endif
