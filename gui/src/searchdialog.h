#ifndef FEAR_SEARCH_DIALOG_H
#define FEAR_SEARCH_DIALOG_H

#include <QDialog>
class QLineEdit;
class QListWidget;
class QLabel;
class QTimer;

namespace fear {

class History;

/**
 * Simple full-text-ish search across the local SQLite history. As the user
 * types (200 ms debounce), we re-run a LIKE %needle% query and dump the
 * top N matches (newest first) into a list. Tap a row → preview as a
 * tooltip; double-click is reserved for "jump to message" once we have
 * multi-room navigation (Phase B).
 */
class SearchDialog : public QDialog {
    Q_OBJECT
public:
    explicit SearchDialog(History *history, QWidget *parent = nullptr);

private slots:
    void rerunQuery();

private:
    History     *m_history;
    QLineEdit   *m_input;
    QLabel      *m_status;
    QListWidget *m_results;
    QTimer      *m_debounce;
};

}  // namespace fear

#endif
