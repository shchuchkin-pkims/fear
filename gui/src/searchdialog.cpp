#include "searchdialog.h"
#include "history.h"

#include <QDateTime>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

namespace fear {

SearchDialog::SearchDialog(History *history, QWidget *parent)
    : QDialog(parent), m_history(history) {

    setWindowTitle(tr("Search messages"));
    resize(640, 480);

    m_input  = new QLineEdit(this);
    m_input->setPlaceholderText(tr("Search…"));
    m_status = new QLabel(this);
    m_status->setStyleSheet("color: gray;");
    m_results = new QListWidget(this);

    auto *layout = new QVBoxLayout(this);
    layout->addWidget(m_input);
    layout->addWidget(m_status);
    layout->addWidget(m_results, /*stretch=*/1);

    auto *btnRow = new QHBoxLayout;
    btnRow->addStretch(1);
    auto *closeBtn = new QPushButton(tr("Close"), this);
    btnRow->addWidget(closeBtn);
    layout->addLayout(btnRow);

    // 200 ms debounce — avoid hitting SQLite on every keystroke.
    m_debounce = new QTimer(this);
    m_debounce->setSingleShot(true);
    m_debounce->setInterval(200);

    connect(m_input,    &QLineEdit::textChanged,    m_debounce, QOverload<>::of(&QTimer::start));
    connect(m_debounce, &QTimer::timeout,           this,       &SearchDialog::rerunQuery);
    connect(closeBtn,   &QPushButton::clicked,      this,       &QDialog::accept);

    rerunQuery();   // start with empty state hint
}

void SearchDialog::rerunQuery() {
    const QString needle = m_input->text().trimmed();
    m_results->clear();
    if (needle.size() < 2) {
        m_status->setText(tr("Type at least 2 characters."));
        return;
    }
    if (!m_history) {
        m_status->setText(tr("History is not available."));
        return;
    }
    const auto hits = m_history->search(needle, 200);
    m_status->setText(tr("%1 matches").arg(hits.size()));

    for (const auto &h : hits) {
        const QString when = QDateTime::fromMSecsSinceEpoch(h.ts)
                                .toString(QStringLiteral("yyyy-MM-dd HH:mm"));
        const QString line = QString("%1 · %2 · %3 — %4")
                                .arg(h.sender, h.roomId, when, h.text);
        auto *item = new QListWidgetItem(line);
        item->setToolTip(h.text);
        m_results->addItem(item);
    }
}

}  // namespace fear
