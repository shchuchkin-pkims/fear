#include "connectiondialog.h"

#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QSettings>
#include <QIntValidator>

namespace fear {

ConnectionDialog::ConnectionDialog(QWidget *parent) : QDialog(parent) {
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

    // Mode toggle row
    auto *modeRow = new QHBoxLayout();
    modeRow->setSpacing(8);
    m_createBtn = new QPushButton(tr("Create"), this);
    m_joinBtn   = new QPushButton(tr("Join"),   this);
    m_manualBtn = new QPushButton(tr("Use key"), this);
    for (QPushButton *b : {m_createBtn, m_joinBtn, m_manualBtn}) {
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

    // Server picker — preset public nodes plus a free-form custom entry.
    // QComboBox::setEditable(true) lets the user type any host they want.
    m_host = new QComboBox(this);
    m_host->setEditable(true);
    m_host->setInsertPolicy(QComboBox::NoInsert);
    m_host->addItem(tr("fear-project.ru — Netherlands (Meppel)"), QStringLiteral("fear-project.ru"));
    m_host->addItem(tr("81.200.28.93 — Russia (Moscow)"),         QStringLiteral("81.200.28.93"));
    m_host->insertSeparator(m_host->count());
    m_host->addItem(tr("Custom server… (type below)"),            QStringLiteral(""));
    m_host->lineEdit()->setPlaceholderText(tr("e.g. fear-project.ru or 192.168.1.1"));
    // When user picks a preset (with non-empty data) — copy that to the line edit.
    // For the "Custom" entry we just clear and let them type.
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

    auto *btnRow = new QHBoxLayout();
    btnRow->addStretch(1);
    m_cancelBtn = new QPushButton(tr("Cancel"), this);
    m_cancelBtn->setProperty("flat", true);
    m_cancelBtn->setFlat(true);
    m_connectBtn = new QPushButton(tr("Connect"), this);
    m_connectBtn->setDefault(true);
    btnRow->addWidget(m_cancelBtn);
    btnRow->addWidget(m_connectBtn);
    root->addLayout(btnRow);

    connect(m_createBtn, &QPushButton::clicked, this, [this]{ setMode(Backend::CREATE_ROOM); });
    connect(m_joinBtn,   &QPushButton::clicked, this, [this]{ setMode(Backend::JOIN_ROOM);   });
    connect(m_manualBtn, &QPushButton::clicked, this, [this]{ setMode(Backend::MANUAL_KEY);  });
    connect(m_cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_connectBtn, &QPushButton::clicked, this, &QDialog::accept);

    loadFromSettings();
    setMode(m_mode);
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
    // Default to the public NL node; user can override.
    m_host->setCurrentText(s.value("host", "fear-project.ru").toString());
    m_port->setText(s.value("port", 8888).toString());
    m_room->setText(s.value("room").toString());
    m_name->setText(s.value("name").toString());
    int storedMode = s.value("mode", int(Backend::CREATE_ROOM)).toInt();
    if (storedMode < 0 || storedMode > Backend::JOIN_ROOM) storedMode = Backend::CREATE_ROOM;
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

}
