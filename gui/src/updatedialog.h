/**
 * @file updatedialog.h
 * @brief Dialog for checking versions and updating F.E.A.R.
 *
 * Provides UI for:
 * - Checking current application version
 * - Running the updater process
 * - Monitoring update progress
 * - Restarting application after update
 */

#ifndef UPDATEDIALOG_H
#define UPDATEDIALOG_H

#include <QDialog>
#include <QTextEdit>
#include <QLabel>
#include <QPushButton>
#include <QProcess>

/**
 * @class UpdateDialog
 * @brief Dialog for version checking and application updates
 *
 * This dialog provides:
 * - Version checking via --version flag on CLI executable
 * - Update functionality by launching updater.exe
 * - Real-time output monitoring during update
 * - Automatic application restart after successful update
 */
class UpdateDialog : public QDialog {
    Q_OBJECT

public:
    /**
     * @brief Constructs an update dialog
     * @param parent Parent widget (optional)
     * @param cliPath Path to CLI executable (optional)
     */
    explicit UpdateDialog(QWidget *parent = nullptr, const QString &cliPath = "");

    /**
     * @brief Destructor - ensures updater process is terminated
     */
    ~UpdateDialog();

    /**
     * @brief Sets the path to the CLI executable
     * @param path Path to fear executable
     */
    void setCliPath(const QString &path);

private slots:
    /**
     * @brief Checks current application version
     *
     * Runs the CLI executable with --version flag and parses output
     * to extract version number. Updates UI with version information.
     */
    void checkVersion();

    /**
     * @brief Runs the updater process
     *
     * Launches updater.exe from ./bin/ directory and monitors its output.
     * After successful update, prompts to restart the application.
     */
    void runUpdater();

    /**
     * @brief Handles output from updater process
     *
     * Reads and displays updater output in real-time.
     */
    void onUpdaterOutput();

    /**
     * @brief Handles updater process completion
     * @param exitCode Process exit code
     * @param exitStatus Process exit status
     *
     * If exit code is 0, prompts to restart application.
     * Otherwise, displays error message.
     */
    void onUpdaterFinished(int exitCode, QProcess::ExitStatus exitStatus);

private:
    /**
     * @brief Restarts the application
     *
     * Starts a new detached instance of the application and closes
     * the current instance.
     */
    void restartApplication();

    /**
     * @brief Cleans up updater process and re-enables buttons
     */
    void cleanupUpdaterProcess();

    /**
     * @brief Parses version number from CLI output
     * @param output Output from --version command
     * @return Parsed version string (e.g., "1.0.0"), or empty if not found
     *
     * Tries multiple regex patterns to extract version:
     * - "Program version: X.Y.Z"
     * - "version X.Y.Z"
     * - "X.Y.Z"
     */
    QString parseVersion(const QString &output);

    QString m_cliPath;           ///< Path to CLI executable
    QString m_currentVersion;    ///< Currently detected version
    QTextEdit *m_versionText;    ///< Display for version info and update output
    QLabel *m_statusLabel;       ///< Status message display
    QPushButton *m_checkButton;  ///< Check version button
    QPushButton *m_updateButton; ///< Run updater button
    QProcess *m_updaterProcess;  ///< Updater process handle
};

#endif // UPDATEDIALOG_H
