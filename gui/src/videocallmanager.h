/**
 * @file videocallmanager.h
 * @brief Manager for video call process lifecycle
 *
 * This class manages the video_call backend process, handling:
 * - Key generation for encrypted video calls
 * - Starting outgoing video calls
 * - Listening for incoming video calls
 * - Process communication and monitoring
 * - Security: keys passed via stdin (not command-line args)
 */

#ifndef VIDEOCALLMANAGER_H
#define VIDEOCALLMANAGER_H

#include <QObject>
#include <QProcess>
#include <QSettings>

/**
 * @class VideoCallManager
 * @brief Manages the video_call backend process
 *
 * Responsibilities:
 * - Spawns and monitors video_call subprocess
 * - Generates cryptographic keys for secure calls
 * - Handles call/listen modes with proper parameter passing
 * - Securely passes encryption keys via stdin
 * - Monitors process output and errors
 * - Manages process lifecycle (start/stop)
 */
class VideoCallManager : public QObject {
    Q_OBJECT

public:
    explicit VideoCallManager(QObject *parent = nullptr);
    ~VideoCallManager();

    /**
     * @brief Generates a new encryption key for video calls
     * @return true if key generated successfully
     */
    bool generateKey();

    /**
     * @brief Starts an outgoing video call
     * @param remoteIp Remote host IP
     * @param remotePort Remote port
     * @param key Encryption key (64 hex chars)
     * @param localPort Local port (0 = auto)
     * @param quality Quality preset: "low", "medium", "high", or empty
     * @param adaptive Enable adaptive quality
     * @param width Custom width (0 = use preset)
     * @param height Custom height (0 = use preset)
     * @param fps Custom FPS (0 = use preset)
     * @param bitrate Custom bitrate in kbps (0 = use preset)
     * @param camera Camera device path (empty = default)
     * @param audioInput Audio input device ID (-1 = default)
     * @param audioOutput Audio output device ID (-1 = default)
     * @param noVideo Disable video
     * @param noAudio Disable audio
     * @return true if call started
     */
    bool startCall(const QString &remoteIp, quint16 remotePort, const QString &key,
                   quint16 localPort = 0, const QString &quality = "medium",
                   bool adaptive = true, int width = 0, int height = 0,
                   int fps = 0, int bitrate = 0, const QString &camera = QString(),
                   int audioInput = -1, int audioOutput = -1,
                   bool noVideo = false, bool noAudio = false);

    /**
     * @brief Starts listening for incoming video calls
     */
    bool startListening(quint16 localPort, const QString &key,
                        const QString &quality = "medium", bool adaptive = true,
                        int width = 0, int height = 0, int fps = 0, int bitrate = 0,
                        const QString &camera = QString(),
                        int audioInput = -1, int audioOutput = -1,
                        bool noVideo = false, bool noAudio = false);

    /**
     * @brief Stops the active call or listening process
     */
    void stopCall();

    /**
     * @brief Checks if a call is currently active
     */
    bool isCallActive() const;

    /**
     * @brief Gets the currently stored encryption key
     */
    QString getCurrentKey() const;

signals:
    void keyGenerated(const QString &key);
    void callStarted();
    void listeningStarted();
    void callStopped();
    void error(const QString &error);
    void output(const QString &message);

private slots:
    void onProcessOutput();
    void onProcessError();
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);

private:
    /**
     * @brief Finds the video_call executable path
     */
    QString findVideoCallApp();

    /**
     * @brief Build common arguments for call/listen
     */
    QStringList buildArgs(const QString &quality, bool adaptive,
                          int width, int height, int fps, int bitrate,
                          const QString &camera, int audioInput, int audioOutput,
                          bool noVideo, bool noAudio) const;

    QProcess *callProcess;
    QString currentKey;
    QSettings *settings;
public:
    QString identityFilePath; ///< Path to identity key (set by Backend)
};

#endif // VIDEOCALLMANAGER_H
