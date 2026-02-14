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
    QComboBox *audioInputCombo;
    QComboBox *audioOutputCombo;

    /* Video tab */
    QComboBox *videoQualityCombo;
    QComboBox *videoCameraCombo;

    /* Privacy tab */
    QCheckBox *showNotificationContentCheck;
    QCheckBox *autoAcceptFilesCheck;

    /* Identity tab */
    QLabel *identityStatusLabel;
    QLabel *fingerprintLabel;
};

#endif // SETTINGSDIALOG_H
