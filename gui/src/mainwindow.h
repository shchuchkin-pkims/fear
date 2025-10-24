/**
 * @file mainwindow.h
 * @brief Main application window for F.E.A.R. GUI
 *
 * Provides the primary user interface for F.E.A.R. messenger, including:
 * - Menu bar and toolbar
 * - Contact list
 * - Chat view
 * - Message input
 * - Connection management
 * - Integration with all subsystems
 */

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QAction>
#include <QSettings>
#include <QFont>
#include <QSystemTrayIcon>
#include <QMenu>
#include "backend.h"

/**
 * @class MainWindow
 * @brief Main application window
 *
 * The MainWindow provides:
 * - Menu system (File, Connection, Audio call, Keys, Chat, Help)
 * - Toolbar with quick actions
 * - Split view: contacts list | chat area
 * - Connection dialogs for client and server modes
 * - Key generation and exchange
 * - Audio call integration
 * - Update checking
 * - Documentation access
 */
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    /**
     * @brief Constructs the main window
     * @param parent Parent widget (optional)
     */
    explicit MainWindow(QWidget *parent = nullptr);

    /**
     * @brief Gets the CLI executable path
     * @return Path to fear CLI executable
     */
    QString getCliPath() const;

protected:
    /**
     * @brief Handles keyboard events
     * @param event Key event
     *
     * F1: Open documentation
     */
    void keyPressEvent(QKeyEvent *event) override;

    /**
     * @brief Handles window state changes
     * @param event State change event
     *
     * Minimizes to tray when window is minimized
     */
    void changeEvent(QEvent *event) override;

private slots:
    // File menu actions
    /**
     * @brief Opens dialog to send a file
     *
     * Prompts user to select a file and sends /sendfile command
     * through the backend.
     */
    void onSendFile();

    /**
     * @brief Clears chat history
     *
     * Prompts for confirmation before clearing.
     */
    void onClearChat();

    /**
     * @brief Opens font selection dialog for chat
     */
    void onFontSettings();

    // Connection menu actions
    /**
     * @brief Opens audio call dialog
     */
    void onAudioCall();

    /**
     * @brief Opens key exchange dialog
     */
    void onKeyExchange();

    /**
     * @brief Creates a server
     *
     * Opens dialog to configure server port and starts listening.
     */
    void onCreateServer();

    /**
     * @brief Connects to a server as client
     *
     * Opens dialog to enter connection parameters (host, port, room,
     * key, name) and initiates connection.
     */
    void onConnect();

    /**
     * @brief Disconnects from server
     */
    void onDisconnect();

    // Message handling
    /**
     * @brief Sends message from input field
     */
    void onSend();

    /**
     * @brief Handles contact list updates
     * @param contacts Updated list of contacts
     */
    void onContactsUpdated(const QStringList &contacts);

    /**
     * @brief Handles new messages from backend
     * @param messages List of new messages
     */
    void onNewMessages(const QStringList &messages);

    /**
     * @brief Handles errors from backend
     * @param error Error message
     */
    void onError(const QString &error);

    /**
     * @brief Refreshes contact list
     */
    void refreshContacts();

    /**
     * @brief Handles contact selection change
     */
    void onSelectContact();

    // Settings
    /**
     * @brief Opens dialog to set CLI executable path
     */
    void onSetCliPath();

    // Keys
    /**
     * @brief Generates a new room key
     *
     * Calls backend to generate key and displays result.
     */
    void onGenKeys();

    /**
     * @brief Handles key generation completion
     * @param key The generated key
     *
     * Displays key in a dialog with copy and save options.
     */
    void onKeyGenerated(const QString &key);

    /**
     * @brief Handles server start notification
     */
    void onServerStarted();

    /**
     * @brief Opens documentation (PDF manual)
     *
     * Opens doc/manual.pdf if available, otherwise shows GitHub link.
     */
    void onOpenDocumentation();

    /**
     * @brief Handles tray icon activation (click)
     * @param reason Activation reason
     */
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);

    /**
     * @brief Shows window from tray
     */
    void showFromTray();

    /**
     * @brief Hides window to tray
     */
    void hideToTray();

private:
    /**
     * @brief Gets currently selected contact name
     * @return Contact name, or empty string if none selected
     */
    QString currentContact();

    /**
     * @brief Creates status bar
     */
    void createStatusBar();

    /**
     * @brief Appends a formatted line to chat view
     * @param line Message line to append
     *
     * Parses format: [HH:MM:SS] Sender: message
     * and applies HTML formatting.
     */
    void appendChatLine(const QString &line);

    /**
     * @brief Creates all menu actions
     */
    void createActions();

    /**
     * @brief Creates menu bar structure
     */
    void createMenus();

    /**
     * @brief Creates toolbar
     */
    void createToolbar();

    /**
     * @brief Creates central widget layout
     *
     * Sets up split view with contacts on left and chat on right.
     */
    void createCentral();

    /**
     * @brief Creates system tray icon
     */
    void createTrayIcon();

    /**
     * @brief Updates tray icon with unread message badge
     */
    void updateTrayIcon();

    Backend *backend;                 ///< Backend for CLI process management
    QListWidget *contactsWidget;      ///< Contact list widget
    QTextEdit *chatView;              ///< Chat history display
    QLineEdit *inputEdit;             ///< Message input field
    QLabel *statusLabel;              ///< Status bar label
    QSettings *appSettings;           ///< Application settings storage

    QAction *connectAction;           ///< Connect action
    QAction *disconnectAction;        ///< Disconnect action
    QAction *clearChatAction;         ///< Clear chat action
    QAction *fontSettingsAction;      ///< Font settings action
    QAction *sendFileAction;          ///< Send file action

    QFont chatFont;                   ///< Chat display font

    // System tray
    QSystemTrayIcon *trayIcon;        ///< System tray icon
    QMenu *trayMenu;                  ///< Tray icon context menu
    int unreadMessages;               ///< Count of unread messages
    bool isHidden;                    ///< Whether window is hidden to tray
};

#endif // MAINWINDOW_H
