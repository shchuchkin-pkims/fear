/**
 * @file audiocallmanager.h
 * @brief Manager for audio call process lifecycle
 *
 * This class manages the audio call backend process, handling:
 * - Key generation for encrypted audio calls
 * - Starting outgoing calls
 * - Listening for incoming calls
 * - Process communication and monitoring
 * - Security: keys passed via stdin (not command-line args)
 */

#ifndef AUDIOCALLMANAGER_H
#define AUDIOCALLMANAGER_H

#include <QObject>
#include <QProcess>
#include <QSettings>

/**
 * @class AudioCallManager
 * @brief Manages the audio call backend process
 *
 * Responsibilities:
 * - Spawns and monitors audio_call subprocess
 * - Generates cryptographic keys for secure calls
 * - Handles call/listen modes with proper parameter passing
 * - Securely passes encryption keys via stdin (not CLI args)
 * - Monitors process output and errors
 * - Manages process lifecycle (start/stop)
 */
class AudioCallManager : public QObject {
    Q_OBJECT

public:
    /**
     * @brief Constructs a new audio call manager
     * @param parent Parent QObject (optional)
     */
    explicit AudioCallManager(QObject *parent = nullptr);

    /**
     * @brief Destructor - ensures process is stopped
     */
    ~AudioCallManager();

    /**
     * @brief Generates a new encryption key for audio calls
     * @return true if key generated successfully, false otherwise
     *
     * The generated key is:
     * - 32 bytes (64 hex characters)
     * - Output to stdout by audio_call genkey
     * - Automatically copied to clipboard
     * - Emits keyGenerated() signal on success
     */
    bool generateKey();

    /**
     * @brief Starts an outgoing audio call
     * @param remoteIp Remote host IP address
     * @param remotePort Remote host port
     * @param key Encryption key (64 hex chars)
     * @param localPort Local port (0 = auto-select)
     * @param inputDevice Audio input device ID (-1 = default)
     * @param outputDevice Audio output device ID (-1 = default)
     * @return true if call started successfully, false otherwise
     *
     * Security: Key is passed via stdin, not command-line arguments,
     * to prevent exposure in process listings.
     */
    bool startCall(const QString &remoteIp, quint16 remotePort, const QString &key,
                   quint16 localPort = 0, int inputDevice = -1, int outputDevice = -1);

    /**
     * @brief Starts listening for incoming audio calls
     * @param localPort Port to listen on
     * @param key Encryption key (64 hex chars)
     * @param inputDevice Audio input device ID (-1 = default)
     * @param outputDevice Audio output device ID (-1 = default)
     * @return true if listening started successfully, false otherwise
     *
     * Security: Key is passed via stdin, not command-line arguments,
     * to prevent exposure in process listings.
     */
    bool startListening(quint16 localPort, const QString &key,
                        int inputDevice = -1, int outputDevice = -1);

    /**
     * @brief Stops the active call or listening process
     *
     * Terminates the audio_call subprocess gracefully, or kills it
     * if it doesn't respond to termination signal.
     */
    void stopCall();

    /**
     * @brief Checks if a call is currently active
     * @return true if process is running, false otherwise
     */
    bool isCallActive() const;

    /**
     * @brief Gets the currently stored encryption key
     * @return Current encryption key (may be empty)
     */
    QString getCurrentKey() const;

signals:
    /**
     * @brief Emitted when a new key is generated
     * @param key The generated 64-character hex key
     */
    void keyGenerated(const QString &key);

    /**
     * @brief Emitted when an outgoing call is started
     */
    void callStarted();

    /**
     * @brief Emitted when listening mode is started
     */
    void listeningStarted();

    /**
     * @brief Emitted when call/listening is stopped
     */
    void callStopped();

    /**
     * @brief Emitted when an error occurs
     * @param error Error message
     */
    void error(const QString &error);

    /**
     * @brief Emitted when process outputs data
     * @param message Output message from audio_call
     */
    void output(const QString &message);

private slots:
    /**
     * @brief Handles stdout from audio_call process
     */
    void onProcessOutput();

    /**
     * @brief Handles stderr from audio_call process
     */
    void onProcessError();

    /**
     * @brief Handles process termination
     * @param exitCode Process exit code
     * @param exitStatus Process exit status
     */
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);

private:
    /**
     * @brief Finds the audio_call executable path
     * @return Path to audio_call executable, or empty string if not found
     *
     * Searches multiple locations:
     * - Application directory
     * - bin/ subdirectory
     * - ../bin/ (build directory structure)
     * - System PATH
     */
    QString findAudioCallApp();

    QProcess *callProcess;   ///< Audio call subprocess
    QString currentKey;      ///< Currently stored encryption key
    QSettings *settings;     ///< Application settings storage
};

#endif // AUDIOCALLMANAGER_H
