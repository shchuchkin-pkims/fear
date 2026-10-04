#ifndef FEAR_GROUP_PARTICIPANTS_DIALOG_H
#define FEAR_GROUP_PARTICIPANTS_DIALOG_H

#include <QDialog>
#include <QStringList>

class QListWidget;
class QListWidgetItem;

namespace fear {

/**
 * Информационный диалог о групповой комнате. Показывает текущий список
 * присутствующих участников (по последнему USER_LIST от сервера). Тап по
 * имени участника эмитит peerSelected(name) — host (ChatWindow) тогда
 * открывает PeerProfileDialog для этого пользователя.
 */
class GroupParticipantsDialog : public QDialog {
    Q_OBJECT
public:
    GroupParticipantsDialog(const QString    &roomTitle,
                            const QStringList &participants,
                            QWidget          *parent = nullptr);

signals:
    void peerSelected(const QString &name);

private:
    QListWidget *m_list;
};

}  // namespace fear

#endif
