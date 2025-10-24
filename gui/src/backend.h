/**
 * @file backend.h
 * @brief Backend for managing F.E.A.R. CLI processes
 *
 * This class manages communication with the F.E.A.R. command-line client
 * and server processes. It handles:
 * - Client connection to chat rooms
 * - Server creation and management
 * - Message sending and receiving
 * - Key generation for room encryption
 * - Process lifecycle and monitoring
 */

#ifndef BACKEND_H
#define BACKEND_H

#include <QObject>
#include <QProcess>
#include <QSettings>
#include <QStringList>
#include "audiocallmanager.h"

/**
 * @class Backend
 * @brief Backend controller for F.E.A.R. CLI processes
 *
 * Responsibilities:
 * - Spawns and manages client/server CLI processes
 * - Handles secure key passing via stdin (not CLI args)
 * - Parses CLI output for messages and status updates
 * - Generates encryption keys for rooms
 * - Manages connection state
 * - Integrates audio call functionality
 */
class Backend : public QObject {
    Q_OBJECT

public:
    /**
     * @brief Constructs a new backend
     * @param parent Parent QObject (optional)
     */
    explicit Backend(QObject *parent = nullptr);

    /**
     * @brief Destructor - ensures processes are terminated
     */
    ~Backend();

    QString cliPath;              ///< Path to fear CLI executable
    bool isConnected;             ///< Current connection state
    AudioCallManager *audioManager; ///< Audio call manager instance

    /**
     * @brief Sets the path to the CLI executable
     * @param path Path to fear executable
     */
    void setCliPath(const QString &path);

    /**
     * @brief Connects to a chat room as a client
     * @param host Server hostname/IP
     * @param port Server port
     * @param room Room name
     * @param key Encryption key (passed via stdin for security)
     * @param name User display name
     * @return true if connection initiated successfully
     *
     * Security: Key is passed via stdin, not command-line arguments,
     * to prevent exposure in process listings.
     */
    bool connectToServer(const QString &host, int port, const QString &room,
                        const QString &key, const QString &name);

    /**
     * @brief Creates a chat server
     * @param port Port to listen on
     * @param name Server name (currently unused)
     * @return true if server started successfully
     */
    bool createServer(int port, const QString &name);

    /**
     * @brief Disconnects from server and stops all processes
     * @return true if disconnect successful
     */
    bool disconnect();

    /**
     * @brief Sends a message to the chat room
     * @param contact Contact name (currently unused)
     * @param message Message text to send
     * @return true if message sent successfully
     *
     * Writes message to client process stdin.
     */
    bool sendMessage(const QString &contact, const QString &message);

    /**
     * @brief Lists contacts in the room
     * @return List of contact names (currently empty)
     *
     * Note: Contact list is updated via contactsUpdated signal
     * when client output is parsed.
     */
    QStringList listContacts();

    /**
     * @brief Gets recent messages
     * @param outLastId Last message ID (output parameter)
     * @return List of recent messages (currently empty)
     *
     * Note: Messages are delivered via newMessages signal
     * as they arrive.
     */
    QStringList getRecentMessages(int &outLastId);

    /**
     * @brief Generates a new encryption key for a room
     * @param outPath Output path (currently unused - key sent to clipboard)
     * @return true if key generated successfully
     *
     * The generated key is:
     * - Output to stdout by CLI genkey command
     * - Automatically copied to clipboard
     * - Emitted via keyGenerated signal
     */
    bool generateKeypair(const QString &outPath);

signals:
    /**
     * @brief Emitted when client successfully connects
     */
    void connected();

    /**
     * @brief Emitted when client disconnects
     */
    void disconnected();

    /**
     * @brief Emitted when server is created successfully
     */
    void serverCreated();

    /**
     * @brief Emitted when a new encryption key is generated
     * @param key The generated key (hex string)
     */
    void keyGenerated(const QString &key);

    /**
     * @brief Emitted when contact list is updated
     * @param contacts List of contact names in the room
     */
    void contactsUpdated(const QStringList &contacts);

    /**
     * @brief Emitted when new messages arrive
     * @param messages List of message strings
     */
    void newMessages(const QStringList &messages);

    /**
     * @brief Emitted when an error occurs
     * @param error Error message
     */
    void error(const QString &error);

private slots:
    /**
     * @brief Handles stdout from client process
     */
    void onClientStdout();

    /**
     * @brief Handles stderr from client process
     */
    void onClientStderr();

    /**
     * @brief Handles client process termination
     * @param exitCode Process exit code
     * @param status Process exit status
     */
    void onClientFinished(int exitCode, QProcess::ExitStatus status);

    /**
     * @brief Handles stdout from server process
     */
    void onServerStdout();

    /**
     * @brief Handles stderr from server process
     */
    void onServerStderr();

    /**
     * @brief Handles server process termination
     * @param exitCode Process exit code
     * @param status Process exit status
     */
    void onServerFinished(int exitCode, QProcess::ExitStatus status);

private:
    /**
     * @brief Parses client output for messages and status updates
     * @param s Output string from client
     *
     * Detects:
     * - [USERS] messages for contact list updates
     * - Error messages
     * - Regular chat messages
     */
    void parseClientOutput(const QString &s);

    QSettings *settings;       ///< Application settings storage
    QProcess *clientProc;      ///< Client process handle
    QProcess *serverProc;      ///< Server process handle
    int lastMessageId;         ///< Last processed message ID
};

#endif // BACKEND_H
