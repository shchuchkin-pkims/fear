#ifndef FEAR_CHATAREA_H
#define FEAR_CHATAREA_H

#include <QFont>
#include <QWidget>
#include <QString>
#include <QDate>
#include <QDateTime>

class QLabel;
class QTextEdit;
class QPushButton;
class QScrollArea;
class QVBoxLayout;

namespace fear {

class Avatar;

struct Message {
    QString sender;
    QString text;
    QDateTime timestamp;
    bool fromSelf = false;
    bool delivered = false;
    bool isSystem = false;
};

class ChatArea : public QWidget {
    Q_OBJECT
public:
    explicit ChatArea(QWidget *parent = nullptr);

    void setChat(const QString &id, const QString &title, const QString &status);
    void clearMessages();
    void appendMessage(const Message &m);
    void showEmptyState(const QString &hint = QString());

    /**
     * Шрифт переписки.
     *
     * Не украшательство: у людей разное зрение и разные экраны, а читать
     * приходится подолгу. Меняется на лету и применяется в том числе к уже
     * показанным сообщениям - иначе выбор вступал бы в силу только со
     * следующей реплики, и человек решил бы, что настройка не работает.
     */
    QFont messageFont() const { return m_messageFont; }
    void  setMessageFont(const QFont &f);

signals:
    void sendRequested(const QString &text);
    void audioCallRequested();
    void videoCallRequested();
    void chatInfoRequested();
    void attachRequested();
    /** Пункт меню «Поиск сообщений» в шапке чата — открывает search dialog. */
    void searchInChatRequested();
    /** Пункт меню «Очистить историю» — стирает локальную историю текущей комнаты. */
    void clearChatRequested();
    /** Emitted when the user clicks a peer's avatar or name inside a
     *  message bubble — used to open the peer profile dialog. */
    void senderClicked(const QString &senderName);
    /** Emitted when the user clicks the avatar or title in the chat
     *  header. Host opens the peer profile (DM) or participants list
     *  (group) accordingly. */
    void headerClicked();

public:
    /** Forward a click from a bubble's avatar/name area. Internal use. */
    void emitSenderClicked(const QString &senderName) { emit senderClicked(senderName); }
    /** Forward a click from the header click area. Internal use. */
    void emitHeaderClicked() { emit headerClicked(); }

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;
    void paintEvent(QPaintEvent *event) override;

private:
    QFont m_messageFont;   ///< шрифт текста сообщений
    /* День последнего показанного сообщения: по нему решается, нужен
     * ли новый разделитель с датой. QDate() значит «лента пуста». */
    QDate m_lastMessageDay;
    void onSendClicked();

    QString      m_chatId;

    // Header
    QWidget     *m_header;
    Avatar      *m_headerAvatar;
    QLabel      *m_titleLbl;
    QLabel      *m_statusLbl;
    QPushButton *m_audioCallBtn;
    QPushButton *m_videoCallBtn;
    QPushButton *m_menuBtn;

    // Body
    QScrollArea *m_scroll;
    QWidget     *m_messagesContainer;
    QVBoxLayout *m_messagesLayout;
    QLabel      *m_emptyHint;

    // Input
    QWidget     *m_inputArea;
    QPushButton *m_attachBtn;
    QTextEdit   *m_input;
    QPushButton *m_emojiBtn;
    QPushButton *m_sendBtn;

    // Включается, когда пользователь у нижнего края. Пока true —
    // каждое новое сообщение тянет scroll вниз (стандартное поведение
    // мессенджеров). Если пользователь прокрутил вверх читать
    // историю — флаг гасится и автоматическая прокрутка не мешает.
    bool m_stickToBottom = true;
};

}

#endif
