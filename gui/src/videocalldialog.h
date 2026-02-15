/**
 * @file videocalldialog.h
 * @brief Dialog for managing encrypted video calls
 *
 * Provides UI for:
 * - Generating encryption keys
 * - Selecting camera and audio devices
 * - Choosing quality presets (Low/Medium/High/Custom)
 * - Adaptive quality toggle
 * - Initiating outgoing video calls
 * - Listening for incoming video calls
 * - Monitoring call status and output
 */

#ifndef VIDEOCALLDIALOG_H
#define VIDEOCALLDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QSpinBox>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QTextEdit>
#include <QCheckBox>
#include <QGroupBox>
#include "videocallmanager.h"

/**
 * @class VideoCallDialog
 * @brief User interface for encrypted video calling
 */
class VideoCallDialog : public QDialog {
    Q_OBJECT

public:
    explicit VideoCallDialog(VideoCallManager *videoManager, QWidget *parent = nullptr,
                             const QString &roomKeyHex = QString());

private slots:
    void onGenerateKey();
    void onKeyGenerated(const QString &key);
    void onStartCall();
    void onStartListening();
    void onStopCall();
    void onCallStarted();
    void onCallStopped();
    void onError(const QString &error);
    void onOutput(const QString &output);
    void refreshDevices();
    void onQualityPresetChanged(int index);

private:
    void setupUI();
    void setupConnections();
    QString findVideoCallApp();

    VideoCallManager *videoManager;

    // Key section
    QGroupBox *keyGroupBox;
    QLineEdit *keyEdit;
    QPushButton *genKeyButton;

    // Device section
    QComboBox *cameraCombo;
    QComboBox *inputDeviceCombo;
    QComboBox *outputDeviceCombo;
    QPushButton *refreshDevicesButton;

    // Quality section
    QComboBox *qualityCombo;
    QCheckBox *adaptiveCheck;
    QWidget *customWidget;
    QSpinBox *widthSpin;
    QSpinBox *heightSpin;
    QSpinBox *fpsSpin;
    QSpinBox *bitrateSpin;

    // Connection section
    QLineEdit *ipEdit;
    QSpinBox *portSpin;
    QSpinBox *localPortSpin;

    // Control buttons
    QPushButton *callButton;
    QPushButton *listenButton;
    QPushButton *stopButton;

    // Status
    QLabel *statusLabel;
    QTextEdit *outputText;
};

#endif // VIDEOCALLDIALOG_H
