/**
 * @file knownkeysdialog.h
 * @brief Dialog for managing known identity keys
 *
 * Provides UI for:
 * - Viewing all trusted keys with fingerprints and verified status
 * - Marking keys as verified
 * - Removing keys
 * - Importing keys from base64 or file
 */

#ifndef KNOWNKEYSDIALOG_H
#define KNOWNKEYSDIALOG_H

#include <QDialog>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>

class KnownKeysDialog : public QDialog {
    Q_OBJECT

public:
    explicit KnownKeysDialog(QWidget *parent = nullptr);

private slots:
    void onVerify();
    void onRemove();
    void onImportKey();
    void refreshTable();

private:
    void setupUI();
    QString knownKeysPath();

    QTableWidget *table;
    QPushButton *verifyBtn;
    QPushButton *removeBtn;
    QPushButton *importBtn;
    QLabel *infoLabel;
};

#endif // KNOWNKEYSDIALOG_H
