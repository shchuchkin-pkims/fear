#include "chatarea.h"

#include "icons.h"
#include "avatar.h"
#include "../theme/theme.h"

#include <QLabel>
#include <QTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QScrollBar>
#include <QPainter>
#include <QPainterPath>
#include <QFontMetrics>
#include <QRegularExpression>
#include <QTextDocument>
#include <QMouseEvent>
#include <QMenu>
#include <QAction>

namespace fear {

namespace {

constexpr int kAvatarSize  = 32;
constexpr int kBubbleMaxW  = 560;
constexpr int kBubbleRadius = 14;

// QFrame subclass that paints its bg as a rounded rect — guarantees rounded
// corners regardless of QSS quirks (palette has no border-radius).
// Color is pulled from the global theme on every paint so bubbles repaint
// correctly on dark/light theme switch.
class RoundedFrame : public QFrame {
public:
    explicit RoundedFrame(bool fromSelf, QWidget *parent = nullptr)
        : QFrame(parent), m_fromSelf(fromSelf) {
        connect(&Theme::instance(), &Theme::modeChanged,
                this, [this](Theme::Mode){ update(); });
    }
protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(Qt::NoPen);
        const Theme &th = Theme::instance();
        p.setBrush(m_fromSelf ? th.bubbleSelf() : th.bubblePeer());
        p.drawRoundedRect(rect(), kBubbleRadius, kBubbleRadius);
    }
private:
    bool m_fromSelf;
};

// Read-only text that wraps at word boundary OR mid-character — needed for
// long unbroken strings like "ааааа..." that QLabel never splits.
// Auto-sizes its height to its document content. Tracks theme for fg color.
class WrappingText : public QTextEdit {
public:
    WrappingText(const QString &text, bool fromSelf, QWidget *parent = nullptr)
        : QTextEdit(parent), m_fromSelf(fromSelf) {
        setReadOnly(true);
        setFrameShape(QFrame::NoFrame);
        setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
        setLineWrapMode(QTextEdit::WidgetWidth);
        setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        viewport()->setAutoFillBackground(false);
        applyThemeColors();
        document()->setDocumentMargin(0);
        setPlainText(text);
        setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
        // Initial height — recalculated whenever width changes.
        connect(document(), &QTextDocument::contentsChanged, this, [this]() { adjustHeight(); });
        connect(&Theme::instance(), &Theme::modeChanged, this,
                [this](Theme::Mode){ applyThemeColors(); });
        adjustHeight();
    }

    bool hasHeightForWidth() const override { return true; }
    int  heightForWidth(int w) const override {
        QTextDocument *d = document();
        d->setTextWidth(w);
        return int(d->size().height()) + 1;
    }

    // Tell the layout the natural width of the text (as if no wrap). The
    // bubble's QVBoxLayout uses this to size itself; the outer bubble's
    // setMaximumWidth then caps it. Result: short text → narrow bubble;
    // long text → bubble grows up to maxWidth, then wraps.
    QSize sizeHint() const override {
        QTextDocument *d = document();
        const qreal saved = d->textWidth();
        d->setTextWidth(-1);
        const int natural = int(d->idealWidth()) + 2;
        d->setTextWidth(saved);
        return QSize(natural, heightForWidth(natural));
    }
    QSize minimumSizeHint() const override { return QSize(40, fontMetrics().height()); }

protected:
    void resizeEvent(QResizeEvent *e) override {
        QTextEdit::resizeEvent(e);
        adjustHeight();
    }

private:
    void adjustHeight() {
        document()->setTextWidth(viewport()->width());
        const int h = int(document()->size().height()) + 1;
        if (h != minimumHeight()) {
            setMinimumHeight(h);
            setMaximumHeight(h);
        }
    }
    void applyThemeColors() {
        const Theme &th = Theme::instance();
        const QColor fg = m_fromSelf ? th.bubbleSelfText() : th.bubblePeerText();
        setStyleSheet(QString("background: transparent; color: %1; font-size: 13px;")
                      .arg(fg.name()));
    }
    bool m_fromSelf;
};

// Clickable wrapper: re-emits mousePress as a signal, so we can attach
// an "open peer profile" handler to the avatar and the sender name without
// subclassing QLabel/Avatar.
class ClickableBox : public QWidget {
public:
    explicit ClickableBox(QWidget *parent, std::function<void()> onClick)
        : QWidget(parent), m_onClick(std::move(onClick)) {
        setCursor(Qt::PointingHandCursor);
    }
protected:
    void mousePressEvent(QMouseEvent *ev) override {
        if (ev->button() == Qt::LeftButton && m_onClick) m_onClick();
        QWidget::mousePressEvent(ev);
    }
private:
    std::function<void()> m_onClick;
};

class MessageBubble : public QWidget {
public:
    explicit MessageBubble(const Message &m,
                           std::function<void(const QString&)> onSenderClick,
                           QWidget *parent = nullptr) : QWidget(parent) {
        const Theme &th = Theme::instance();
        const bool fromSelf = m.fromSelf;
        const bool showSender = !fromSelf && !m.sender.isEmpty();

        auto *outer = new QHBoxLayout(this);
        outer->setContentsMargins(8, 4, 12, 4);
        outer->setSpacing(8);

        if (fromSelf) outer->addStretch(1);

        const QString senderForCb = m.sender;
        auto fireSenderClick = [onSenderClick, senderForCb]() {
            if (onSenderClick && !senderForCb.isEmpty()) onSenderClick(senderForCb);
        };

        if (!fromSelf) {
            // Wrap avatar in a ClickableBox so users can tap it to see the
            // peer's profile.
            auto *avHolder = new ClickableBox(this, fireSenderClick);
            auto *avHolderLay = new QVBoxLayout(avHolder);
            avHolderLay->setContentsMargins(0, 0, 0, 0);
            avHolderLay->setSpacing(0);
            auto *av = new Avatar(avHolder);
            av->setSeed(m.sender);
            av->setDiameter(kAvatarSize);
            avHolderLay->addWidget(av, 0, Qt::AlignTop);

            auto *avBox = new QVBoxLayout();
            avBox->setContentsMargins(0, 0, 0, 0);
            avBox->setSpacing(0);
            avBox->addWidget(avHolder, 0, Qt::AlignTop);
            avBox->addStretch(1);
            outer->addLayout(avBox);
        }

        // Custom-painted rounded bubble — see RoundedFrame above. Color
        // queried from Theme on each paint, so theme switch redraws live.
        m_bubble = new RoundedFrame(fromSelf, this);
        m_bubble->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);

        auto *bubbleLay = new QVBoxLayout(m_bubble);
        bubbleLay->setContentsMargins(12, 8, 12, 6);
        bubbleLay->setSpacing(2);

        if (showSender) {
            // Wrap the sender name in a ClickableBox too so clicking either
            // the avatar or the name opens the profile dialog.
            auto *nameHolder = new ClickableBox(m_bubble, fireSenderClick);
            auto *nameLay = new QHBoxLayout(nameHolder);
            nameLay->setContentsMargins(0, 0, 0, 0);
            nameLay->setSpacing(0);
            auto *senderLbl = new QLabel(m.sender, nameHolder);
            /* Qt::AutoText renders anything that looks like HTML as rich text, and
             * the sender name comes from the network. A peer named
             * "<img src=http://attacker/x>" would make us fetch that URL on
             * render, leaking the user's IP and online status. */
            senderLbl->setTextFormat(Qt::PlainText);
            QFont sf = senderLbl->font();
            sf.setWeight(QFont::DemiBold);
            sf.setPixelSize(12);
            senderLbl->setFont(sf);
            senderLbl->setStyleSheet(QString("color: %1; background: transparent;")
                .arg(th.avatarColor(m.sender).name()));
            nameLay->addWidget(senderLbl);
            nameLay->addStretch(1);
            bubbleLay->addWidget(nameHolder);
        }

        // Render U+2028 (LINE SEPARATOR) as a normal newline — it's how we
        // ferry multiline messages past the CLI's line-based stdin reader.
        QString displayText = m.text;
        displayText.replace(QChar(0x2028), QChar('\n'));

        // WrappingText breaks at character boundary too — so long runs without
        // spaces (like "ааааа..." or URLs) wrap inside the bubble width.
        auto *textLbl = new WrappingText(displayText, fromSelf, m_bubble);
        bubbleLay->addWidget(textLbl);

        QString metaText;
        if (m.timestamp.isValid()) metaText = m.timestamp.toString("HH:mm");
        if (fromSelf) metaText += m.delivered ? "  ✓✓" : "  ✓";
        if (!metaText.isEmpty()) {
            auto *metaLbl = new QLabel(metaText, m_bubble);
            metaLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            auto applyMeta = [metaLbl]() {
                metaLbl->setStyleSheet(QString("color: %1; background: transparent; font-size: 11px;")
                    .arg(Theme::instance().textSecondary().name()));
            };
            applyMeta();
            QObject::connect(&Theme::instance(), &Theme::modeChanged, metaLbl,
                             [applyMeta](Theme::Mode){ applyMeta(); });
            bubbleLay->addWidget(metaLbl);
        }

        outer->addWidget(m_bubble, 0, Qt::AlignTop);

        if (!fromSelf) outer->addStretch(1);
    }

protected:
    void resizeEvent(QResizeEvent *e) override {
        QWidget::resizeEvent(e);
        // Cap bubble at ~42% of available width — visible gap between self/peer
        // bubbles, no overlap. Floor of 120px so very-narrow windows don't kill it.
        if (m_bubble) m_bubble->setMaximumWidth(qMax(120, int(width() * 0.42)));
    }

private:
    QFrame *m_bubble = nullptr;
};

/**
 * Дата над первым сообщением дня.
 *
 * Одного времени «14:03» мало: по нему не видно, сегодняшнее это сообщение
 * или недельной давности, а открытая переписка спокойно переваливает за
 * полночь. То же самое и теми же словами делает приложение на телефоне.
 */
class DaySeparator : public QWidget {
public:
    DaySeparator(const QDate &day, QWidget *parent = nullptr) : QWidget(parent) {
        auto *lay = new QHBoxLayout(this);
        lay->setContentsMargins(24, 6, 24, 6);
        lay->addStretch(1);

        auto *pill = new QLabel(label(day), this);
        pill->setAlignment(Qt::AlignCenter);
        const Theme &th = Theme::instance();
        pill->setStyleSheet(QString(
            "background: %1; color: %2; border-radius: 10px;"
            " padding: 4px 12px; font-size: 12px; font-weight: 600;")
            .arg(th.mode() == Theme::Light ? QStringLiteral("rgba(255,255,255,200)")
                                           : QStringLiteral("rgba(58,61,66,220)"),
                 th.textSecondary().name()));
        lay->addWidget(pill);
        lay->addStretch(1);
    }

    /**
     * «Today», «Yesterday» или сама дата.
     *
     * Год пишется только когда он не нынешний - иначе он стоит в каждом
     * разделителе и ни о чём не говорит. Считаем календарём, а не вычитанием
     * суток: «вчера» в день перевода часов длится 23 часа или 25.
     */
    static QString label(const QDate &day) {
        const QDate today = QDate::currentDate();
        if (day == today) return tr("Today");
        if (day == today.addDays(-1)) return tr("Yesterday");
        const QString fmt = (day.year() == today.year())
                                ? QStringLiteral("d MMMM")
                                : QStringLiteral("d MMMM yyyy");
        return QLocale().toString(day, fmt);
    }

private:
    Q_DISABLE_COPY(DaySeparator)
};

QPushButton *makeIconButton(fear::Glyph glyph, const QString &tooltip,
                            QWidget *parent, int size = 36) {
    auto *b = new QPushButton(parent);
    b->setProperty("flat", true);
    b->setFlat(true);
    b->setFixedSize(size, size);
    b->setCursor(Qt::PointingHandCursor);
    b->setToolTip(tooltip);
    /* Цвет берётся у темы в момент создания. Переключение темы пересоздаёт
     * окно, так что перекрашивать значки на лету не нужно. */
    b->setIcon(fear::icon(glyph, Theme::instance().textSecondary(), 20));
    b->setIconSize(QSize(20, 20));
    return b;
}

} // anon

ChatArea::ChatArea(QWidget *parent) : QWidget(parent) {
    setObjectName("ChatArea");

    // ─── Header ───
    m_header = new QWidget(this);
    m_header->setObjectName("ChatHeader");
    m_header->setAttribute(Qt::WA_StyledBackground, true);
    // Guarantee the bg fills regardless of QSS — palette wins over inheritance.
    m_header->setAutoFillBackground(true);
    m_header->setFixedHeight(54);

    m_headerAvatar = new Avatar(m_header);
    m_headerAvatar->setDiameter(36);

    m_titleLbl = new QLabel(m_header);
    m_titleLbl->setObjectName("ChatTitle");

    m_statusLbl = new QLabel(m_header);
    m_statusLbl->setObjectName("ChatStatus");

    auto *titleCol = new QVBoxLayout();
    titleCol->setContentsMargins(0, 0, 0, 0);
    titleCol->setSpacing(0);
    titleCol->addWidget(m_titleLbl);
    titleCol->addWidget(m_statusLbl);

    m_audioCallBtn = makeIconButton(fear::Glyph::Phone, tr("Audio call"), m_header);
    m_videoCallBtn = makeIconButton(fear::Glyph::Video, tr("Video call"), m_header);
    m_menuBtn      = makeIconButton(fear::Glyph::More, tr("More"),       m_header);

    // Кликабельная зона: аватар + title — единый clickable контейнер.
    // Тап → headerClicked(), хост открывает профиль собеседника
    // (для ЛС) или диалог участников (для групповой комнаты).
    auto *clickable = new ClickableBox(m_header, [this]() { emitHeaderClicked(); });
    auto *clickableLay = new QHBoxLayout(clickable);
    clickableLay->setContentsMargins(0, 0, 0, 0);
    clickableLay->setSpacing(10);
    clickableLay->addWidget(m_headerAvatar);
    clickableLay->addLayout(titleCol, 1);

    auto *headerLay = new QHBoxLayout(m_header);
    headerLay->setContentsMargins(12, 8, 12, 8);
    headerLay->setSpacing(10);
    headerLay->addWidget(clickable, 1);
    headerLay->addWidget(m_audioCallBtn);
    headerLay->addWidget(m_videoCallBtn);
    headerLay->addWidget(m_menuBtn);

    // ─── Messages scroll ───
    m_scroll = new QScrollArea(this);
    m_scroll->setObjectName("MessagesScroll");
    m_scroll->setWidgetResizable(true);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    // Make the scroll area + its viewport transparent so the parent
    // ChatArea's paintEvent (which paints the gradient/solid bg) shows through.
    m_scroll->setStyleSheet("background: transparent; border: none;");
    m_scroll->viewport()->setAutoFillBackground(false);
    m_scroll->viewport()->setStyleSheet("background: transparent;");

    m_messagesContainer = new QWidget(m_scroll);
    m_messagesContainer->setObjectName("MessagesContainer");
    m_messagesContainer->setAttribute(Qt::WA_TranslucentBackground, true);
    m_messagesLayout = new QVBoxLayout(m_messagesContainer);
    m_messagesLayout->setContentsMargins(0, 8, 0, 8);
    m_messagesLayout->setSpacing(2);
    m_messagesLayout->addStretch(1);

    m_scroll->setWidget(m_messagesContainer);

    // Авто-прокрутка к нижнему краю при добавлении сообщения. После
    // вставки нового bubble layout пересчитает range scrollbar-а и
    // сигнал rangeChanged даст нам гарантированный момент, когда
    // maximum уже актуален. До этого мы прокручиваем «оптимистично»
    // в appendMessage(), но maximum часто ещё старый. Подписка
    // решает оба случая.
    connect(m_scroll->verticalScrollBar(), &QScrollBar::rangeChanged,
            this, [this](int /*min*/, int max) {
        // Прокручиваем только когда юзер уже у нижнего края — иначе
        // он не сможет читать историю выше: каждое новое сообщение
        // выбрасывало бы его обратно в самый низ.
        auto *bar = m_scroll->verticalScrollBar();
        if (m_stickToBottom) bar->setValue(max);
    });
    connect(m_scroll->verticalScrollBar(), &QScrollBar::valueChanged,
            this, [this](int v) {
        auto *bar = m_scroll->verticalScrollBar();
        // 4 пикселя — терпимая неточность для трекпада.
        m_stickToBottom = (v >= bar->maximum() - 4);
    });

    m_emptyHint = new QLabel(this);
    m_emptyHint->setObjectName("EmptyChatHint");
    m_emptyHint->setAlignment(Qt::AlignCenter);
    m_emptyHint->setText(tr("Select a chat to start messaging"));

    // Show empty state by default
    m_scroll->hide();
    m_header->hide();

    // ─── Input ───
    m_inputArea = new QWidget(this);
    m_inputArea->setObjectName("InputArea");
    m_inputArea->setAttribute(Qt::WA_StyledBackground, true);
    m_inputArea->setAutoFillBackground(true);
    m_inputArea->setMinimumHeight(54);

    // Sync header + input bg to current theme. Re-apply on theme switch so
    // a Light↔Dark toggle redraws them without restart.
    auto applyPanelBg = [this]() {
        const Theme &th = Theme::instance();
        const QColor bg = th.sidebarBackground();
        const QColor fg = th.textPrimary();
        for (QWidget *w : {m_header, m_inputArea}) {
            QPalette p = w->palette();
            p.setColor(QPalette::Window,     bg);
            p.setColor(QPalette::WindowText, fg);   // labels inherit this
            p.setColor(QPalette::Text,       fg);
            p.setColor(QPalette::ButtonText, fg);
            w->setPalette(p);
        }
        // Also repaint the chat area (gradient/solid bg) on theme change.
        update();
    };
    applyPanelBg();
    connect(&Theme::instance(), &Theme::modeChanged, this,
            [applyPanelBg](Theme::Mode){ applyPanelBg(); });

    m_attachBtn = makeIconButton(fear::Glyph::Attach, tr("Attach"), m_inputArea);
    m_emojiBtn  = makeIconButton(fear::Glyph::Smile, tr("Emoji"),  m_inputArea);
    m_sendBtn   = makeIconButton(fear::Glyph::Send, tr("Send"),   m_inputArea);
    m_sendBtn->setObjectName("SendButton");

    // Rounded pill container — auto-grows in height with the input text up to
    // a cap (~5 lines), then scrolls. The QTextEdit lives inside fully
    // transparent so the pill bg shows through.
    auto *inputPill = new QFrame(m_inputArea);
    inputPill->setObjectName("MessagePill");
    inputPill->setAttribute(Qt::WA_StyledBackground, true);
    inputPill->setMinimumHeight(38);

    m_input = new QTextEdit(inputPill);
    m_input->setObjectName("MessageInput");
    m_input->setPlaceholderText(tr("Write a message..."));
    m_input->setFrameShape(QFrame::NoFrame);
    m_input->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_input->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_input->setTabChangesFocus(true);
    m_input->setAcceptRichText(false);
    m_input->viewport()->setAutoFillBackground(false);
    // Enter sends, Shift+Enter inserts a newline (handled in eventFilter).
    m_input->installEventFilter(this);

    // Auto-grow as user types more lines; cap at kInputMaxH to start scrolling.
    static constexpr int kInputMinH = 26;
    static constexpr int kInputMaxH = 140; // ~6 lines with default font
    auto adjustInputHeight = [this, inputPill]() {
        QTextDocument *doc = m_input->document();
        doc->setTextWidth(m_input->viewport()->width());
        int docH = int(doc->size().height());
        // Doc + a tiny pad; clamp.
        int h = qBound(kInputMinH, docH + 4, kInputMaxH);
        if (h != m_input->minimumHeight()) {
            m_input->setMinimumHeight(h);
            m_input->setMaximumHeight(h);
            inputPill->setMinimumHeight(h + 12);
            inputPill->setMaximumHeight(h + 12);
        }
    };
    connect(m_input, &QTextEdit::textChanged, this, adjustInputHeight);
    QMetaObject::invokeMethod(this, adjustInputHeight, Qt::QueuedConnection);

    auto *pillLay = new QHBoxLayout(inputPill);
    pillLay->setContentsMargins(14, 4, 14, 4);
    pillLay->setSpacing(0);
    pillLay->addWidget(m_input);

    auto *inputLay = new QHBoxLayout(m_inputArea);
    inputLay->setContentsMargins(8, 8, 8, 8);
    inputLay->setSpacing(8);
    inputLay->addWidget(m_attachBtn);
    inputLay->addWidget(inputPill, 1);
    inputLay->addWidget(m_emojiBtn);
    inputLay->addWidget(m_sendBtn);

    m_inputArea->hide();

    // ─── Root layout ───
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    root->addWidget(m_header);
    root->addWidget(m_emptyHint, 1);
    root->addWidget(m_scroll, 1);
    root->addWidget(m_inputArea);

    connect(m_sendBtn,      &QPushButton::clicked, this, &ChatArea::onSendClicked);
    connect(m_audioCallBtn, &QPushButton::clicked, this, &ChatArea::audioCallRequested);
    connect(m_videoCallBtn, &QPushButton::clicked, this, &ChatArea::videoCallRequested);
    // Меню действий, относящихся к текущему чату. Открывается под кнопкой «⋮».
    connect(m_menuBtn, &QPushButton::clicked, this, [this]() {
        QMenu menu(this);
        QAction *aSearch = menu.addAction(tr("Search messages…"));
        QAction *aClear  = menu.addAction(tr("Clear chat history…"));
        QPoint pos = m_menuBtn->mapToGlobal(QPoint(0, m_menuBtn->height()));
        QAction *picked = menu.exec(pos);
        if      (picked == aSearch) emit searchInChatRequested();
        else if (picked == aClear)  emit clearChatRequested();
    });
    connect(m_attachBtn,    &QPushButton::clicked, this, &ChatArea::attachRequested);
}

void ChatArea::setChat(const QString &id, const QString &title, const QString &status) {
    m_chatId = id;
    /* Room/peer titles are network-controlled - keep them out of rich text. */
    m_titleLbl->setTextFormat(Qt::PlainText);
    m_statusLbl->setTextFormat(Qt::PlainText);
    m_titleLbl->setText(title);
    m_statusLbl->setText(status);
    m_headerAvatar->setSeed(title);

    m_emptyHint->hide();
    m_header->show();
    m_scroll->show();
    m_inputArea->show();
}

void ChatArea::clearMessages() {
    /* Лента пуста - значит следующее сообщение снова первое в своём дне. */
    m_lastMessageDay = QDate();
    while (m_messagesLayout->count() > 1) {
        QLayoutItem *item = m_messagesLayout->takeAt(0);
        if (QWidget *w = item->widget()) w->deleteLater();
        delete item;
    }
}

void ChatArea::appendMessage(const Message &m) {
    /* Разделитель ставится перед первым сообщением дня. Сравнивается
     * календарный день, а не сама метка времени: час по обе стороны от
     * полуночи - это два разных дня при разнице меньше суток. */
    const QDate day = m.timestamp.isValid() ? m.timestamp.date()
                                            : QDate::currentDate();
    if (day != m_lastMessageDay) {
        auto *sep = new DaySeparator(day, m_messagesContainer);
        m_messagesLayout->insertWidget(m_messagesLayout->count() - 1, sep);
        m_lastMessageDay = day;
    }

    ChatArea *self = this;
    auto onSenderClick = [self](const QString &name) {
        self->emitSenderClicked(name);
    };
    auto *bubble = new MessageBubble(m, onSenderClick, m_messagesContainer);
    bubble->setMinimumHeight(34);
    m_messagesLayout->insertWidget(m_messagesLayout->count() - 1, bubble);

    // Scroll to bottom on next event loop pass
    QMetaObject::invokeMethod(this, [this]() {
        auto *bar = m_scroll->verticalScrollBar();
        bar->setValue(bar->maximum());
    }, Qt::QueuedConnection);
}

void ChatArea::showEmptyState(const QString &hint) {
    if (!hint.isEmpty()) m_emptyHint->setText(hint);
    m_emptyHint->show();
    m_header->hide();
    m_scroll->hide();
    m_inputArea->hide();
}

void ChatArea::onSendClicked() {
    QString txt = m_input->toPlainText().trimmed();
    if (txt.isEmpty()) return;
    // The CLI reads stdin line-by-line via fgets() — embedded '\n' chars would
    // split the message into N separate sends with the tail buffered until the
    // next user input. Replace '\n' with U+2028 (LINE SEPARATOR): multi-byte
    // UTF-8 with no 0x0A byte, so fgets() reads the whole thing as one line,
    // and QLabel/text rendering still treats it as a visual line break.
    txt.replace(QChar('\n'), QChar(0x2028));
    emit sendRequested(txt);
    m_input->clear();
}

void ChatArea::paintEvent(QPaintEvent *event) {
    QWidget::paintEvent(event);
    QPainter p(this);
    const Theme &th = Theme::instance();
    if (th.mode() == Theme::Light) {
        // Telegram-light style: vertical green gradient (lighter at top).
        QLinearGradient g(0, 0, 0, height());
        g.setColorAt(0.0, QColor("#E8F5DC"));
        g.setColorAt(1.0, QColor("#B7DDA0"));
        p.fillRect(rect(), g);
    } else {
        // Dark: flat darker fill.
        p.fillRect(rect(), th.chatBackground());
    }
}

bool ChatArea::eventFilter(QObject *obj, QEvent *event) {
    if (obj == m_input && event->type() == QEvent::KeyPress) {
        auto *ke = static_cast<QKeyEvent*>(event);
        const bool isEnter = (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter);
        if (isEnter && !(ke->modifiers() & Qt::ShiftModifier)) {
            // Enter alone → send. Shift+Enter falls through to default newline.
            onSendClicked();
            return true;
        }
    }
    return QWidget::eventFilter(obj, event);
}

}
