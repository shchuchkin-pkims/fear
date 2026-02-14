/**
 * @file settingsdialog.cpp
 * @brief Implementation of Settings dialog
 */

#include "settingsdialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QLabel>
#include <QLineEdit>
#include <QFileDialog>
#include <QMessageBox>
#include <QProcess>
#include <sodium.h>

#ifdef Q_OS_WIN
#define FEAR_DIR (QDir::homePath() + "/AppData/Roaming/fear")
#else
#define FEAR_DIR (QDir::homePath() + "/.fear")
#endif

SettingsDialog::SettingsDialog(QSettings *settings, QWidget *parent)
    : QDialog(parent), settings(settings) {
    setWindowTitle("Settings");
    setMinimumSize(500, 400);

    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    QTabWidget *tabs = new QTabWidget(this);
    setupGeneralTab(tabs);
    setupChatTab(tabs);
    setupAudioTab(tabs);
    setupVideoTab(tabs);
    setupPrivacyTab(tabs);
    setupIdentityTab(tabs);
    mainLayout->addWidget(tabs);

    /* Buttons */
    QHBoxLayout *btnLayout = new QHBoxLayout();
    btnLayout->addStretch();
    QPushButton *okBtn = new QPushButton("OK", this);
    QPushButton *applyBtn = new QPushButton("Apply", this);
    QPushButton *cancelBtn = new QPushButton("Cancel", this);
    btnLayout->addWidget(okBtn);
    btnLayout->addWidget(applyBtn);
    btnLayout->addWidget(cancelBtn);
    mainLayout->addLayout(btnLayout);

    connect(okBtn, &QPushButton::clicked, this, &SettingsDialog::onOk);
    connect(applyBtn, &QPushButton::clicked, this, &SettingsDialog::onApply);
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);

    loadSettings();
}

void SettingsDialog::setupGeneralTab(QTabWidget *tabs) {
    QWidget *page = new QWidget();
    QFormLayout *form = new QFormLayout(page);

    QGroupBox *cliGroup = new QGroupBox("CLI executable");
    QHBoxLayout *cliLayout = new QHBoxLayout(cliGroup);

    cliPathEdit = new QLineEdit();
    cliPathEdit->setReadOnly(true);
    cliPathEdit->setPlaceholderText("Path to fear CLI executable");
    QPushButton *browseBtn = new QPushButton("Browse...");
    connect(browseBtn, &QPushButton::clicked, this, &SettingsDialog::onBrowseCliPath);

    cliLayout->addWidget(cliPathEdit);
    cliLayout->addWidget(browseBtn);
    form->addRow(cliGroup);

    QLabel *note = new QLabel("Path to the F.E.A.R. CLI executable used for chat, key generation, and identity.");
    note->setWordWrap(true);
    note->setStyleSheet("color: gray; font-size: 11px;");
    form->addRow(note);

    tabs->addTab(page, "General");
}

void SettingsDialog::onBrowseCliPath() {
#ifdef Q_OS_WIN
    QString file = QFileDialog::getOpenFileName(this, "Select CLI executable",
                       QString(), "Executable files (*.exe);;All files (*)");
#else
    QString file = QFileDialog::getOpenFileName(this, "Select CLI executable",
                       QString(), "All files (*)");
#endif
    if (!file.isEmpty()) {
        cliPathEdit->setText(file);
    }
}

void SettingsDialog::setupChatTab(QTabWidget *tabs) {
    QWidget *page = new QWidget();
    QFormLayout *form = new QFormLayout(page);

    QGroupBox *fontGroup = new QGroupBox("Font");
    QFormLayout *fontForm = new QFormLayout(fontGroup);

    fontCombo = new QFontComboBox();
    fontSizeSpin = new QSpinBox();
    fontSizeSpin->setRange(6, 48);
    fontSizeSpin->setValue(10);

    fontForm->addRow("Font family:", fontCombo);
    fontForm->addRow("Font size:", fontSizeSpin);
    form->addRow(fontGroup);

    tabs->addTab(page, "Chat");
}

void SettingsDialog::setupAudioTab(QTabWidget *tabs) {
    QWidget *page = new QWidget();
    QFormLayout *form = new QFormLayout(page);

    QGroupBox *devGroup = new QGroupBox("Default audio devices");
    QFormLayout *devForm = new QFormLayout(devGroup);

    audioInputCombo = new QComboBox();
    audioOutputCombo = new QComboBox();

    /* Populate with generic options; actual device list from audio_call */
    audioInputCombo->addItem("System default");
    audioOutputCombo->addItem("System default");

    /* Try to get device list from audio_call binary */
    QString audioCallPath;
#ifdef Q_OS_WIN
    audioCallPath = "./bin/audio_call.exe";
#else
    audioCallPath = "./bin/audio_call";
#endif
    if (QFileInfo(audioCallPath).isFile()) {
        QProcess p;
        p.setProcessChannelMode(QProcess::ForwardedErrorChannel);
        p.start(audioCallPath, QStringList() << "listdevices");
        if (p.waitForFinished(3000)) {
            QString out = QString::fromUtf8(p.readAllStandardOutput());
            QStringList lines = out.split('\n', Qt::SkipEmptyParts);
            for (const QString &line : lines) {
                QString trimmed = line.trimmed();
                if (!trimmed.isEmpty() && !trimmed.startsWith("Input") &&
                    !trimmed.startsWith("Output") && !trimmed.startsWith("---")) {
                    /* Try to detect input vs output sections */
                    if (trimmed.contains("(input)", Qt::CaseInsensitive) ||
                        trimmed.startsWith("  ")) {
                        audioInputCombo->addItem(trimmed.simplified());
                        audioOutputCombo->addItem(trimmed.simplified());
                    } else {
                        audioInputCombo->addItem(trimmed.simplified());
                        audioOutputCombo->addItem(trimmed.simplified());
                    }
                }
            }
        }
    }

    devForm->addRow("Input device:", audioInputCombo);
    devForm->addRow("Output device:", audioOutputCombo);
    form->addRow(devGroup);

    QLabel *note = new QLabel("Device selection is applied when starting audio/video calls.");
    note->setWordWrap(true);
    note->setStyleSheet("color: gray; font-size: 11px;");
    form->addRow(note);

    tabs->addTab(page, "Audio");
}

void SettingsDialog::setupVideoTab(QTabWidget *tabs) {
    QWidget *page = new QWidget();
    QFormLayout *form = new QFormLayout(page);

    QGroupBox *qualGroup = new QGroupBox("Video quality");
    QFormLayout *qualForm = new QFormLayout(qualGroup);

    videoQualityCombo = new QComboBox();
    videoQualityCombo->addItem("Low (320x240, 15 fps)", "low");
    videoQualityCombo->addItem("Medium (640x480, 25 fps)", "medium");
    videoQualityCombo->addItem("High (1280x720, 30 fps)", "high");

    qualForm->addRow("Quality preset:", videoQualityCombo);
    form->addRow(qualGroup);

    /* Default camera device */
    QGroupBox *camGroup = new QGroupBox("Default camera");
    QFormLayout *camForm = new QFormLayout(camGroup);

    videoCameraCombo = new QComboBox();
    videoCameraCombo->addItem("Default", "");

    /* Enumerate cameras via video_call listdevices */
    QString videoCallPath;
#ifdef Q_OS_WIN
    videoCallPath = "./bin/video_call.exe";
#else
    videoCallPath = "./bin/video_call";
#endif
    if (QFileInfo(videoCallPath).isFile()) {
        QProcess p;
        p.setProcessChannelMode(QProcess::ForwardedErrorChannel);
        p.start(videoCallPath, QStringList() << "listdevices");
        if (p.waitForFinished(3000)) {
            QString out = QString::fromUtf8(p.readAllStandardOutput());
            QStringList lines = out.split('\n', Qt::SkipEmptyParts);
            bool inCameraSection = false;
            for (const QString &line : lines) {
                QString t = line.trimmed();
                if (t.startsWith("=== Camera")) {
                    inCameraSection = true;
                    continue;
                }
                if (t.startsWith("===")) {
                    inCameraSection = false;
                    continue;
                }
                if (inCameraSection && t.startsWith("camera:")) {
                    QString camName = t.mid(7).trimmed();
                    if (!camName.isEmpty() && camName != "(no cameras found)") {
                        videoCameraCombo->addItem(camName, camName);
                    }
                }
            }
        }
    }

    camForm->addRow("Camera device:", videoCameraCombo);
    form->addRow(camGroup);

    QLabel *note = new QLabel("Quality and camera settings are applied when starting new video calls.\n"
                              "Higher quality requires more bandwidth.");
    note->setWordWrap(true);
    note->setStyleSheet("color: gray; font-size: 11px;");
    form->addRow(note);

    tabs->addTab(page, "Video");
}

void SettingsDialog::setupPrivacyTab(QTabWidget *tabs) {
    QWidget *page = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page);

    QGroupBox *notifGroup = new QGroupBox("Notifications");
    QVBoxLayout *notifLayout = new QVBoxLayout(notifGroup);

    showNotificationContentCheck = new QCheckBox("Show message content in popup notifications");
    QLabel *notifNote = new QLabel("When disabled, notifications only show \"New message\" without text content.\n"
                                   "Enable to see message preview in notification popups.");
    notifNote->setWordWrap(true);
    notifNote->setStyleSheet("color: gray; font-size: 11px;");
    notifLayout->addWidget(showNotificationContentCheck);
    notifLayout->addWidget(notifNote);
    layout->addWidget(notifGroup);

    QGroupBox *fileGroup = new QGroupBox("File transfers");
    QVBoxLayout *fileLayout = new QVBoxLayout(fileGroup);

    autoAcceptFilesCheck = new QCheckBox("Auto-accept incoming file transfers");
    QLabel *fileNote = new QLabel("When disabled, you will be asked to accept or reject each incoming file.\n"
                                  "When enabled, files are saved to Downloads automatically.");
    fileNote->setWordWrap(true);
    fileNote->setStyleSheet("color: gray; font-size: 11px;");
    fileLayout->addWidget(autoAcceptFilesCheck);
    fileLayout->addWidget(fileNote);
    layout->addWidget(fileGroup);

    layout->addStretch();
    tabs->addTab(page, "Privacy");
}

void SettingsDialog::setupIdentityTab(QTabWidget *tabs) {
    QWidget *page = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(page);

    QGroupBox *idGroup = new QGroupBox("Identity key (Ed25519)");
    QVBoxLayout *idLayout = new QVBoxLayout(idGroup);

    identityStatusLabel = new QLabel();
    fingerprintLabel = new QLabel();
    fingerprintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    fingerprintLabel->setStyleSheet("font-family: monospace; font-size: 13px;");

    /* Check identity status */
    QString identityPath = FEAR_DIR + "/identity";
    if (QFile::exists(identityPath)) {
        identityStatusLabel->setText("Identity key: <b style='color:#2ecc71'>Available</b>");

        /* Try to read public key and compute fingerprint */
        QFile idFile(identityPath);
        if (idFile.open(QIODevice::ReadOnly)) {
            QByteArray data = idFile.readAll();
            idFile.close();
            if ((size_t)data.size() >= crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES) {
                /* identity file = pk(32) + sk(64) */
                unsigned char pk[crypto_sign_PUBLICKEYBYTES];
                memcpy(pk, data.constData(), crypto_sign_PUBLICKEYBYTES);

                /* BLAKE2b fingerprint (first 8 bytes) */
                unsigned char hash[8];
                crypto_generichash(hash, sizeof(hash), pk, crypto_sign_PUBLICKEYBYTES, NULL, 0);
                QString fp;
                for (int i = 0; i < 8; i++) {
                    if (i > 0) fp += ":";
                    fp += QString("%1").arg(hash[i], 2, 16, QChar('0'));
                }
                fingerprintLabel->setText("Fingerprint: " + fp);
            }
        }
    } else {
        identityStatusLabel->setText("Identity key: <b style='color:#e74c3c'>Not generated</b>");
        fingerprintLabel->setText("Generate an identity key from Keys menu to enable message signing.");
    }

    idLayout->addWidget(identityStatusLabel);
    idLayout->addWidget(fingerprintLabel);

    /* Known keys info */
    QString knownKeysPath = FEAR_DIR + "/known_keys";
    if (QFile::exists(knownKeysPath)) {
        QFile kf(knownKeysPath);
        if (kf.open(QIODevice::ReadOnly)) {
            QByteArray content = kf.readAll();
            kf.close();
            int count = content.split('\n').count() - 1;
            if (count < 0) count = 0;
            QLabel *knownLabel = new QLabel(QString("Known trusted keys: %1").arg(count));
            idLayout->addWidget(knownLabel);
        }
    }

    layout->addWidget(idGroup);
    layout->addStretch();
    tabs->addTab(page, "Identity");
}

void SettingsDialog::loadSettings() {
    /* General */
#ifdef Q_OS_WIN
    cliPathEdit->setText(settings->value("cli/path", "fear.exe").toString());
#else
    cliPathEdit->setText(settings->value("cli/path", "fear").toString());
#endif

    /* Chat */
    QString fontFamily = settings->value("chat/fontFamily", "Arial").toString();
    int fontSize = settings->value("chat/fontSize", 10).toInt();
    fontCombo->setCurrentFont(QFont(fontFamily));
    fontSizeSpin->setValue(fontSize);

    /* Audio */
    QString audioIn = settings->value("audio/inputDevice", "System default").toString();
    QString audioOut = settings->value("audio/outputDevice", "System default").toString();
    int idx = audioInputCombo->findText(audioIn);
    if (idx >= 0) audioInputCombo->setCurrentIndex(idx);
    idx = audioOutputCombo->findText(audioOut);
    if (idx >= 0) audioOutputCombo->setCurrentIndex(idx);

    /* Video */
    QString quality = settings->value("video/quality", "medium").toString();
    for (int i = 0; i < videoQualityCombo->count(); i++) {
        if (videoQualityCombo->itemData(i).toString() == quality) {
            videoQualityCombo->setCurrentIndex(i);
            break;
        }
    }
    QString defaultCamera = settings->value("video/defaultCamera", "").toString();
    for (int i = 0; i < videoCameraCombo->count(); i++) {
        if (videoCameraCombo->itemData(i).toString() == defaultCamera) {
            videoCameraCombo->setCurrentIndex(i);
            break;
        }
    }

    /* Privacy */
    showNotificationContentCheck->setChecked(
        settings->value("privacy/showNotificationContent", false).toBool());
    autoAcceptFilesCheck->setChecked(
        settings->value("privacy/autoAcceptFiles", false).toBool());
}

void SettingsDialog::saveSettings() {
    /* General — CLI path */
    QString newCliPath = cliPathEdit->text();
    QString oldCliPath = settings->value("cli/path").toString();
    settings->setValue("cli/path", newCliPath);
    if (newCliPath != oldCliPath) {
        emit cliPathChanged(newCliPath);
    }

    /* Chat */
    settings->setValue("chat/fontFamily", fontCombo->currentFont().family());
    settings->setValue("chat/fontSize", fontSizeSpin->value());

    QFont newFont(fontCombo->currentFont().family(), fontSizeSpin->value());
    /* Also save in the format used by mainwindow */
    settings->setValue("chat/font", newFont.toString());
    emit chatFontChanged(newFont);

    /* Audio */
    settings->setValue("audio/inputDevice", audioInputCombo->currentText());
    settings->setValue("audio/outputDevice", audioOutputCombo->currentText());

    /* Video */
    settings->setValue("video/quality",
                       videoQualityCombo->currentData().toString());
    settings->setValue("video/defaultCamera",
                       videoCameraCombo->currentData().toString());

    /* Privacy */
    settings->setValue("privacy/showNotificationContent",
                       showNotificationContentCheck->isChecked());
    settings->setValue("privacy/autoAcceptFiles",
                       autoAcceptFilesCheck->isChecked());
}

void SettingsDialog::onApply() {
    saveSettings();
}

void SettingsDialog::onOk() {
    saveSettings();
    accept();
}
