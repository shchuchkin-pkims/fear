#include "connectiondialog.h"
#include "profilesettings.h"
#include "profiledialog.h"
#include "registerhandledialog.h"
#include "widgets/avatar.h"

#include <QEvent>
#include <QMouseEvent>

#include <QComboBox>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QHBoxLayout>
#include <QIntValidator>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QTimer>
#include <QVBoxLayout>
#include <QtConcurrent>

extern "C" {
#include "identity.h"
#include "server_proto.h"
}

namespace fear {

namespace {
struct ProbeResult {
    quint64     seq = 0;
    sp_status_t status = SP_NETWORK_ERROR;
    QString     handle;
};
}

ConnectionDialog::ConnectionDialog(ProfileSettings *profile,
                                   const QString   &identityPath,
                                   QWidget         *parent)
    : QDialog(parent),
      m_profile(profile),
      m_identityPath(identityPath)
{
    setWindowTitle(tr("Connect to F.E.A.R."));
    setModal(true);
    setMinimumWidth(460);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(24, 20, 24, 20);
    root->setSpacing(14);

    auto *heading = new QLabel(tr("Connect to a room"), this);
    QFont hf = heading->font();
    hf.setPixelSize(20);
    hf.setWeight(QFont::Medium);
    heading->setFont(hf);
    root->addWidget(heading);

    auto *subtitle = new QLabel(
        tr("Choose how you want to enter a room. Create a fresh one, "
           "join an existing room (we'll fetch the key), or paste a key you have."),
        this);
    subtitle->setObjectName("DialogSubtitle");
    subtitle->setWordWrap(true);
    root->addWidget(subtitle);

    /* ── Identity-карточка ───────────────────────────────────────
     * Показывает имя пользователя и подсказку «Click to edit profile».
     * Тап открывает ProfileDialog для редактирования display name и
     * управления зарегистрированными handle-ами. */
    m_identityCard = new QWidget(this);
    m_identityCard->setCursor(Qt::PointingHandCursor);
    m_identityCard->setObjectName("IdentityCard");
    m_identityCard->setStyleSheet(QStringLiteral(
        "QWidget#IdentityCard { background: rgba(255,255,255,0.05);"
        "                        border-radius: 8px; padding: 8px; }"
        "QWidget#IdentityCard:hover { background: rgba(255,255,255,0.08); }"));
    auto *cardLay = new QHBoxLayout(m_identityCard);
    cardLay->setContentsMargins(10, 8, 10, 8);
    cardLay->setSpacing(12);

    m_identityAvatar = new Avatar(m_identityCard);
    m_identityAvatar->setDiameter(40);
    cardLay->addWidget(m_identityAvatar);

    auto *idTextCol = new QVBoxLayout();
    idTextCol->setContentsMargins(0, 0, 0, 0);
    idTextCol->setSpacing(2);
    m_identityNameLbl = new QLabel(m_identityCard);
    QFont nf = m_identityNameLbl->font();
    nf.setPixelSize(15);
    nf.setWeight(QFont::DemiBold);
    m_identityNameLbl->setFont(nf);
    m_identityHintLbl = new QLabel(tr("Click to edit profile"), m_identityCard);
    m_identityHintLbl->setStyleSheet(QStringLiteral("color: gray; font-size: 11px;"));
    idTextCol->addWidget(m_identityNameLbl);
    idTextCol->addWidget(m_identityHintLbl);
    cardLay->addLayout(idTextCol, 1);

    /* Делаем сам контейнер кликабельным через event-filter обёртку. */
    m_identityCard->installEventFilter(this);
    root->addWidget(m_identityCard);
    refreshIdentityCard();

    /* Mode toggle row */
    auto *modeRow = new QHBoxLayout();
    modeRow->setSpacing(8);
    m_autoBtn   = new QPushButton(tr("Auto"),   this);
    m_createBtn = new QPushButton(tr("Create"), this);
    m_joinBtn   = new QPushButton(tr("Join"),   this);
    m_manualBtn = new QPushButton(tr("Use key"), this);
    m_autoBtn->setToolTip(tr(
        "Probe the server: empty room → Create, otherwise → Join. No more "
        "5-second blind wait when starting a fresh chat."));
    for (QPushButton *b : {m_autoBtn, m_createBtn, m_joinBtn, m_manualBtn}) {
        b->setObjectName("ModeButton");
        b->setCheckable(true);
        b->setCursor(Qt::PointingHandCursor);
        b->setMinimumHeight(40);
        modeRow->addWidget(b);
    }
    root->addLayout(modeRow);

    auto *form = new QFormLayout();
    form->setLabelAlignment(Qt::AlignLeft);
    form->setHorizontalSpacing(12);
    form->setVerticalSpacing(10);
    form->setFormAlignment(Qt::AlignTop);

    m_host = new QComboBox(this);
    m_host->setEditable(true);
    m_host->setInsertPolicy(QComboBox::NoInsert);
    /* Порядок в списке и значение по умолчанию - разные вещи, и здесь они
     * намеренно разведены. В списке первой идёт Москва; подставляется же в
     * поле Меппел (см. ниже, при восстановлении настроек). */
    m_host->addItem(tr("fear-project.ru — Russia (Moscow)"),     QStringLiteral("fear-project.ru"));
    m_host->addItem(tr("77.221.145.132 — Netherlands (Meppel)"), QStringLiteral("77.221.145.132"));
    m_host->insertSeparator(m_host->count());
    m_host->addItem(tr("Custom server… (type below)"),            QStringLiteral(""));
    m_host->lineEdit()->setPlaceholderText(tr("or type your own: host name or address"));
    connect(m_host, QOverload<int>::of(&QComboBox::activated), this, [this](int idx) {
        const QString preset = m_host->itemData(idx).toString();
        if (!preset.isEmpty()) m_host->setEditText(preset);
        else                   m_host->clearEditText();
    });

    m_port = new QLineEdit(this);
    m_port->setValidator(new QIntValidator(1, 65535, this));
    m_port->setPlaceholderText("8888");
    m_port->setMaximumWidth(120);

    m_room = new QLineEdit(this);
    m_room->setPlaceholderText(tr("Room name"));

    m_name = new QLineEdit(this);
    m_name->setPlaceholderText(tr("Your display name"));

    m_keyLabel = new QLabel(tr("Room key (base64):"), this);
    m_key = new QPlainTextEdit(this);
    m_key->setPlaceholderText(tr("Paste the room key here"));
    m_key->setFixedHeight(64);

    form->addRow(tr("Server"), m_host);
    form->addRow(tr("Port"),   m_port);
    form->addRow(tr("Room"),   m_room);
    form->addRow(tr("Name"),   m_name);
    form->addRow(m_keyLabel,   m_key);

    root->addLayout(form);

    /* Status line — shows whether we are registered on the chosen host. */
    m_statusLabel = new QLabel(this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet(QStringLiteral("color: gray;"));
    root->addWidget(m_statusLabel);

    auto *btnRow = new QHBoxLayout();
    btnRow->addStretch(1);
    m_cancelBtn = new QPushButton(tr("Cancel"), this);
    m_cancelBtn->setProperty("flat", true);
    m_cancelBtn->setFlat(true);
    m_registerBtn = new QPushButton(tr("Register"), this);
    m_connectBtn  = new QPushButton(tr("Connect"), this);
    m_connectBtn->setDefault(true);
    btnRow->addWidget(m_cancelBtn);
    btnRow->addWidget(m_registerBtn);
    btnRow->addWidget(m_connectBtn);
    root->addLayout(btnRow);

    connect(m_autoBtn,   &QPushButton::clicked, this, [this]{ setMode(Backend::AUTO);        });
    connect(m_createBtn, &QPushButton::clicked, this, [this]{ setMode(Backend::CREATE_ROOM); });
    connect(m_joinBtn,   &QPushButton::clicked, this, [this]{ setMode(Backend::JOIN_ROOM);   });
    connect(m_manualBtn, &QPushButton::clicked, this, [this]{ setMode(Backend::MANUAL_KEY);  });
    connect(m_cancelBtn,   &QPushButton::clicked, this, &QDialog::reject);
    connect(m_connectBtn,  &QPushButton::clicked, this, &QDialog::accept);
    connect(m_registerBtn, &QPushButton::clicked, this, &ConnectionDialog::onRegisterClicked);

    /* Registration probe: debounce typing into the host field by ~400 ms
     * so we don't spam the relay on every keystroke. */
    m_probeDebounce = new QTimer(this);
    m_probeDebounce->setSingleShot(true);
    m_probeDebounce->setInterval(400);
    connect(m_probeDebounce, &QTimer::timeout, this, &ConnectionDialog::runRegistrationProbe);

    connect(m_host->lineEdit(), &QLineEdit::textChanged, this,
            [this](const QString &) { onHostChanged(); });
    connect(m_port, &QLineEdit::textChanged, this,
            [this](const QString &) { onHostChanged(); });

    loadFromSettings();
    setMode(m_mode);

    /* First-paint status: read whatever ProfileSettings already knows, then
     * kick a probe to refresh from the server. */
    setRegistrationStatus(RegUnknown);
    onHostChanged();
}

QString ConnectionDialog::host() const { return m_host->currentText().trimmed(); }
int     ConnectionDialog::port() const { return m_port->text().toInt(); }
QString ConnectionDialog::room() const { return m_room->text().trimmed(); }
QString ConnectionDialog::name() const { return m_name->text().trimmed(); }
QString ConnectionDialog::key()  const { return m_key->toPlainText().trimmed(); }

void ConnectionDialog::setMode(Backend::ConnectMode m) {
    m_mode = m;
    updateModeUi();
}

void ConnectionDialog::updateModeUi() {
    m_autoBtn->setChecked  (m_mode == Backend::AUTO);
    m_createBtn->setChecked(m_mode == Backend::CREATE_ROOM);
    m_joinBtn->setChecked  (m_mode == Backend::JOIN_ROOM);
    m_manualBtn->setChecked(m_mode == Backend::MANUAL_KEY);

    const bool needKey = (m_mode == Backend::MANUAL_KEY);
    m_keyLabel->setVisible(needKey);
    m_key->setVisible(needKey);
    adjustSize();
}

void ConnectionDialog::loadFromSettings() {
    QSettings s("fear-messenger", "fear-gui");
    s.beginGroup("connect");
    /* Подставляется Меппел - это сервер по умолчанию, независимо от того,
     * каким по счёту он стоит в списке.
     *
     * Запомненный адрес важнее: человек, выбравший себе сервер, не должен
     * возвращаться к чужому после каждого запуска. */
    m_host->setCurrentText(s.value("host", "77.221.145.132").toString());
    m_port->setText(s.value("port", 8888).toString());
    m_room->setText(s.value("room", "general").toString());
    m_name->setText(s.value("name").toString());
    int storedMode = s.value("mode", int(Backend::AUTO)).toInt();
    if (storedMode < 0 || storedMode > Backend::AUTO) storedMode = Backend::AUTO;
    m_mode = Backend::ConnectMode(storedMode);
    s.endGroup();
}

void ConnectionDialog::saveToSettings() const {
    QSettings s("fear-messenger", "fear-gui");
    s.beginGroup("connect");
    s.setValue("host", host());
    s.setValue("port", port());
    s.setValue("room", room());
    s.setValue("name", name());
    s.setValue("mode", int(m_mode));
    s.endGroup();
}

/* ---------- Registration logic ---------- */

void ConnectionDialog::onHostChanged() {
    /* Step 1 — instantly reflect what we already know locally. */
    if (m_profile) {
        const QString h = m_profile->handleFor(host());
        if (!h.isEmpty()) setRegistrationStatus(RegYes, h);
        else              setRegistrationStatus(RegUnknown);
    }
    /* Step 2 — schedule a server probe to verify or correct the local view. */
    scheduleRegistrationProbe();
}

void ConnectionDialog::scheduleRegistrationProbe() {
    m_probeDebounce->start();
}

void ConnectionDialog::runRegistrationProbe() {
    if (host().isEmpty() || port() <= 0) {
        setRegistrationStatus(RegUnknown);
        return;
    }
    setRegistrationStatus(RegProbing);

    const quint64    mySeq = ++m_probeSeq;
    const QByteArray hb    = host().toUtf8();
    const uint16_t   prt   = static_cast<uint16_t>(port());
    const QByteArray ip    = m_identityPath.toUtf8();

    auto *watcher = new QFutureWatcher<ProbeResult>(this);
    connect(watcher, &QFutureWatcher<ProbeResult>::finished, this,
            [this, watcher, mySeq]() {
        watcher->deleteLater();
        if (mySeq != m_probeSeq) return; /* superseded by a later probe */
        const ProbeResult r = watcher->result();
        if (r.status == SP_OK && !r.handle.isEmpty()) {
            if (m_profile) m_profile->markRegisteredAs(host(), r.handle);
            setRegistrationStatus(RegYes, r.handle);
        } else if (r.status == SP_NOT_FOUND) {
            if (m_profile) m_profile->forgetRegistration(host());
            setRegistrationStatus(RegNo);
        } else {
            /* network error, bad reply, etc. — don't pretend, but don't
             * lock the user out either: fall back to the locally cached
             * value if we have one. */
            const QString cached = m_profile ? m_profile->handleFor(host()) : QString();
            if (!cached.isEmpty()) setRegistrationStatus(RegYes, cached);
            else                   setRegistrationStatus(RegError);
        }
    });

    auto future = QtConcurrent::run([hb, prt, ip, mySeq]() -> ProbeResult {
        ProbeResult r; r.seq = mySeq;
        uint8_t pk[IDENTITY_PK_BYTES];
        if (identity_load_pk(ip.constData(), pk) != 0) {
            r.status = SP_INVALID;
            return r;
        }
        char handle[64] = {0};
        r.status = sp_lookup_handle_by_pk(hb.constData(), prt, pk, handle, sizeof(handle));
        if (r.status == SP_OK) r.handle = QString::fromUtf8(handle);
        return r;
    });
    watcher->setFuture(future);
}

void ConnectionDialog::setRegistrationStatus(RegStatus st, const QString &handle) {
    m_regStatus = st;
    m_currentHandle = handle;
    switch (st) {
        case RegYes:
            m_statusLabel->setText(tr("Registered as @%1@%2 on this server.")
                                       .arg(handle, host()));
            m_statusLabel->setStyleSheet(QStringLiteral("color: #2e7d32;"));
            break;
        case RegNo:
            m_statusLabel->setText(tr("Registration is required to enter this server. "
                                      "Pick a short name and click Register."));
            m_statusLabel->setStyleSheet(QStringLiteral("color: #c62828;"));
            break;
        case RegProbing:
            m_statusLabel->setText(tr("Checking registration status…"));
            m_statusLabel->setStyleSheet(QStringLiteral("color: gray;"));
            break;
        case RegError:
            m_statusLabel->setText(tr("Cannot reach the server to verify registration. "
                                      "You can still try to connect."));
            m_statusLabel->setStyleSheet(QStringLiteral("color: #ef6c00;"));
            break;
        case RegUnknown:
        default:
            m_statusLabel->setText(tr("Enter a server to check your registration status."));
            m_statusLabel->setStyleSheet(QStringLiteral("color: gray;"));
            break;
    }
    refreshButtons();
}

void ConnectionDialog::refreshButtons() {
    /* Audit 2026-07 (UX-High): Connect must not hard-lock on an inconclusive
     * probe. Only a definite "not registered" keeps it disabled - in every
     * other state the server itself is the authority and will answer. */
    const bool canConnect  = (m_regStatus != RegNo);
    const bool canRegister = (m_regStatus == RegNo);
    m_connectBtn->setEnabled(canConnect);
    m_registerBtn->setEnabled(canRegister);
}

bool ConnectionDialog::eventFilter(QObject *obj, QEvent *ev) {
    if (obj == m_identityCard && ev->type() == QEvent::MouseButtonRelease) {
        onIdentityCardClicked();
        return true;
    }
    return QDialog::eventFilter(obj, ev);
}

void ConnectionDialog::refreshIdentityCard() {
    if (!m_identityCard) return;
    const QString name = m_profile ? m_profile->displayName() : QString();
    const QString shown = name.isEmpty() ? tr("Set your name") : name;
    m_identityAvatar->setSeed(shown);
    m_identityNameLbl->setText(shown);
}

void ConnectionDialog::onIdentityCardClicked() {
    if (!m_profile) return;
    /* Backup-flow доступен из главного меню чата; здесь оставляем
     * пустые callback-и — пользователь редактирует только имя и
     * управляет списком зарегистрированных handle-ов. */
    ProfileDialog dlg(m_profile, m_identityPath,
                      /*onExport=*/ [](){},
                      /*onShowQr=*/ [](){},
                      /*defaultHost=*/ host(),
                      /*defaultPort=*/ static_cast<uint16_t>(qMax(1, port())),
                      this);
    dlg.exec();
    refreshIdentityCard();
    /* Если пользователь сменил handle (зарегистрировал новый из
     * ProfileDialog), статус-строка должна это сразу подхватить. */
    onHostChanged();
}

void ConnectionDialog::onRegisterClicked() {
    if (host().isEmpty() || port() <= 0) return;
    /* Suggest the current display name as a starting point — the user can
     * override before submitting. */
    const QString suggest = m_profile ? m_profile->displayName().toLower() : QString();
    RegisterHandleDialog dlg(host(), static_cast<uint16_t>(port()),
                             m_identityPath, suggest, this);
    if (dlg.exec() != QDialog::Accepted) return;
    const QString chosen = dlg.chosenHandle();
    if (chosen.isEmpty()) return;
    if (m_profile) m_profile->markRegisteredAs(host(), chosen);
    setRegistrationStatus(RegYes, chosen);
}

}  // namespace fear
