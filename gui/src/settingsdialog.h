/**
 * @file settingsdialog.h
 * @brief Settings dialog for F.E.A.R. GUI
 *
 * Tabbed settings dialog with:
 * - Chat: font settings
 * - Audio: default input/output device
 * - Video: quality preset
 * - Privacy: notification content toggle, identity info
 */

#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include <QTabWidget>
#include <QSettings>
#include <QFontComboBox>
#include <QSlider>
#include <QSpinBox>
#include <QComboBox>
#include <QCheckBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>

class SettingsDialog : public QDialog {
    Q_OBJECT

public:
    explicit SettingsDialog(QSettings *settings, QWidget *parent = nullptr);

signals:
    void chatFontChanged(const QFont &font);
    void cliPathChanged(const QString &path);

private slots:
    void onApply();
    void onOk();
    void onBrowseCliPath();

private:
    void setupGeneralTab(QTabWidget *tabs);
    void setupChatTab(QTabWidget *tabs);
    void setupAudioTab(QTabWidget *tabs);
    void setupVideoTab(QTabWidget *tabs);
    void setupPrivacyTab(QTabWidget *tabs);
    void setupIdentityTab(QTabWidget *tabs);
    void loadSettings();
    void saveSettings();

    QSettings *settings;

    /* General tab */
    QLineEdit *cliPathEdit;

    /* Chat tab */
    QFontComboBox *fontCombo;
    QSpinBox *fontSizeSpin;

    /* Audio tab */
    /* Микрофон: чувствительность и подавление фона. Микрофоны у людей
     * разные - гарнитура у рта и микрофон в крышке ноутбука отличаются на
     * добрый десяток децибел, - а автоматика системы выравнивает это не
     * всегда. Поэтому руками. */
    QSlider   *micGainSlider = nullptr;
    QLabel    *micGainValue  = nullptr;
    QComboBox *noiseSuppressCombo = nullptr;

    QComboBox *audioInputCombo;
    QComboBox *audioOutputCombo;

    /* Video tab */
    /* Сервер STUN: пусто - звонки идут через ретранслятор. */
    /* Внешний слой TLS для связи с ретранслятором. */
    QCheckBox *tlsCheck = nullptr;
    QLineEdit *tlsPinEdit = nullptr;

    QLineEdit *stunServerEdit = nullptr;

    QComboBox *videoQualityCombo;
    /* Ручное качество: готовые наборы покрывают обычные случаи, но не все.
     * Узкий канал, слабая камера или, наоборот, гигабитная сеть - там нужны
     * свои числа, а не ближайший из трёх. */
    QWidget   *manualVideoBox = nullptr;
    QSpinBox  *videoWidthSpin = nullptr;
    QSpinBox  *videoHeightSpin = nullptr;
    QSpinBox  *videoFpsSpin = nullptr;
    QSpinBox  *videoBitrateSpin = nullptr;
    QComboBox *videoCameraCombo;

    /* Privacy tab */
    QCheckBox *showNotificationContentCheck;
    QCheckBox *autoAcceptFilesCheck;

    /* Identity tab */
    QLabel *identityStatusLabel;
    QLabel *fingerprintLabel;
};

#endif // SETTINGSDIALOG_H
