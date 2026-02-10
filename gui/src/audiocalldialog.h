/**
 * @file audiocalldialog.h
 * @brief Dialog for managing encrypted audio calls
 *
 * Provides UI for:
 * - Generating encryption keys
 * - Selecting audio input/output devices
 * - Initiating outgoing calls
 * - Listening for incoming calls
 * - Monitoring call status and output
 */

#ifndef AUDIOCALLDIALOG_H
#define AUDIOCALLDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QSpinBox>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QTextEdit>
#include "audiocallmanager.h"

/**
 * @class AudioCallDialog
 * @brief User interface for encrypted audio calling
 *
 * This dialog provides a complete interface for managing secure audio calls:
 * - Key generation and display
 * - Audio device selection (input/output)
 * - Connection parameters (IP, ports)
 * - Call/listen control buttons
 * - Status monitoring and log output
 *
 * The dialog communicates with AudioCallManager to control the audio_call
 * subprocess.
 */
class AudioCallDialog : public QDialog {
    Q_OBJECT

public:
    /**
     * @brief Constructs an audio call dialog
     * @param audioManager Manager for audio call processes
     * @param parent Parent widget (optional)
     */
    explicit AudioCallDialog(AudioCallManager *audioManager, QWidget *parent = nullptr);

private slots:
    /**
     * @brief Generates a new encryption key
     */
    void onGenerateKey();

    /**
     * @brief Handles key generation completion
     * @param key The generated 64-character hex key
     */
    void onKeyGenerated(const QString &key);

    /**
     * @brief Starts an outgoing audio call
     *
     * Validates input fields and initiates call to remote IP:port
     * using the specified encryption key and audio devices.
     */
    void onStartCall();

    /**
     * @brief Starts listening for incoming calls
     *
     * Validates key and starts listening on local port with
     * specified audio devices.
     */
    void onStartListening();

    /**
     * @brief Stops the active call or listening session
     */
    void onStopCall();

    /**
     * @brief Handles call start event
     *
     * Updates UI state when call/listening begins.
     */
    void onCallStarted();

    /**
     * @brief Handles call stop event
     *
     * Updates UI state when call/listening ends.
     */
    void onCallStopped();

    /**
     * @brief Handles error messages from audio manager
     * @param error Error message to display
     */
    void onError(const QString &error);

    /**
     * @brief Handles output messages from audio process
     * @param output Output message to display
     */
    void onOutput(const QString &output);

    /**
     * @brief Refreshes the list of available audio devices
     *
     * Queries audio_call listdevices and populates device combo boxes
     */
    void refreshAudioDevices();

private:
    /**
     * @brief Sets up the user interface widgets
     *
     * Creates and arranges all UI elements:
     * - Encryption key section
     * - Audio device selection
     * - Connection parameters
     * - Control buttons
     * - Status and output display
     */
    void setupUI();

    /**
     * @brief Sets up signal/slot connections
     *
     * Connects:
     * - Audio manager signals to dialog slots
     * - UI button clicks to action slots
     */
    void setupConnections();

    /**
     * @brief Finds the audio_call executable
     * @return Path to audio_call, or empty string if not found
     */
    QString findAudioCallApp();

    // Manager
    AudioCallManager *audioManager;  ///< Audio call process manager

    // Encryption key widgets
    QLineEdit *keyEdit;              ///< Encryption key input (64 hex chars)
    QPushButton *genKeyButton;       ///< Generate key button

    // Audio device widgets
    QComboBox *inputDeviceCombo;     ///< Input device selection
    QComboBox *outputDeviceCombo;    ///< Output device selection
    QPushButton *refreshDevicesButton; ///< Refresh device list button

    // Connection widgets
    QLineEdit *ipEdit;               ///< Remote IP address
    QSpinBox *portSpin;              ///< Remote port
    QSpinBox *localPortSpin;         ///< Local port

    // Control buttons
    QPushButton *callButton;         ///< Start call button
    QPushButton *listenButton;       ///< Start listening button
    QPushButton *stopButton;         ///< Stop button

    // Status display
    QLabel *statusLabel;             ///< Current status message
    QTextEdit *outputText;           ///< Log output from audio process
};

#endif // AUDIOCALLDIALOG_H
