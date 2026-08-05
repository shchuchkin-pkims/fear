/**
 * @file adminwindow.h
 * @brief Окно утилиты администрирования ретранслятора.
 *
 * Пять вкладок по тому, что в базе действительно есть: занятые имена,
 * зашифрованные блобы, заблокированные ключи, живые подключения и сводка.
 * Переписки среди них нет и быть не может - сервер её не хранит, и об этом
 * сказано прямо во вкладке «Сводка», потому что это первое, чего от такой
 * утилиты ждут.
 */
#ifndef FEAR_ADMIN_WINDOW_H
#define FEAR_ADMIN_WINDOW_H

#include <QMainWindow>

#include "serverdb.h"

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTimer;

class AdminWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit AdminWindow(QWidget *parent = nullptr);

    bool openDatabase(const QString &path);

private slots:
    void chooseDatabase();
    void refreshAll();
    void refreshSessions();

    void deleteSelectedHandles();
    void blockSelectedHandles();
    void deleteSelectedBlobs();
    void unblockSelected();
    void blockByFingerprint();
    void exportHandles();
    void compactDatabase();

private:
    void buildUi();
    void setBusy(const QString &message);
    void showError(const QString &what, const QString &detail);
    /** Ключи выделенных строк таблицы: они лежат в UserRole первой колонки. */
    QList<QByteArray> selectedKeys(QTableWidget *table) const;

    void fillHandles();
    void fillBlobs();
    void fillBlocked();
    void fillOverview();

    ServerDb m_db;

    QTableWidget *m_handles  = nullptr;
    QTableWidget *m_blobs    = nullptr;
    QTableWidget *m_blocks   = nullptr;
    QTableWidget *m_sessions = nullptr;

    QLineEdit *m_filter      = nullptr;
    QLabel    *m_overview    = nullptr;
    QLabel    *m_serverState = nullptr;
    QTimer    *m_sessionTimer = nullptr;
};

#endif
