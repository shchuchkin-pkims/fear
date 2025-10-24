/**
 * @file updatedialog.cpp
 * @brief Implementation of update dialog
 */

#include "updatedialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QApplication>
#include <QFile>
#include <QFileInfo>
#include <QTextCursor>
#include <QRegularExpression>
#include <QDebug>

UpdateDialog::UpdateDialog(QWidget *parent, const QString &cliPath)
    : QDialog(parent), m_cliPath(cliPath) {
    setWindowTitle("Check for Updates");
    setMinimumSize(600, 500);

    QVBoxLayout *layout = new QVBoxLayout(this);

    // Title
    QLabel *titleLabel = new QLabel("F.E.A.R. Messenger - Version Information", this);
    titleLabel->setStyleSheet("font-size: 14px;");
    layout->addWidget(titleLabel);

    // Text field for version information
    m_versionText = new QTextEdit(this);
    m_versionText->setReadOnly(true);
    m_versionText->setPlaceholderText("Click 'Check Version' to get version information...");
    layout->addWidget(m_versionText);

    // Status
    m_statusLabel = new QLabel("Ready to check version", this);
    layout->addWidget(m_statusLabel);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();

    m_checkButton = new QPushButton("Check Version", this);
    m_updateButton = new QPushButton("Update", this);
    QPushButton *closeButton = new QPushButton("Close", this);

    m_updateButton->setEnabled(false);

    buttonLayout->addWidget(m_checkButton);
    buttonLayout->addWidget(m_updateButton);
    buttonLayout->addWidget(closeButton);
    layout->addLayout(buttonLayout);

    // Connect signals
    connect(m_checkButton, &QPushButton::clicked, this, &UpdateDialog::checkVersion);
    connect(m_updateButton, &QPushButton::clicked, this, &UpdateDialog::runUpdater);
    connect(closeButton, &QPushButton::clicked, this, &UpdateDialog::accept);

    // Initialize process
    m_updaterProcess = nullptr;
}

UpdateDialog::~UpdateDialog() {
    if (m_updaterProcess) {
        if (m_updaterProcess->state() == QProcess::Running) {
            m_updaterProcess->kill();
            m_updaterProcess->waitForFinished(1000);
        }
        m_updaterProcess->deleteLater();
    }
}

void UpdateDialog::setCliPath(const QString &path) {
    m_cliPath = path;
}

void UpdateDialog::checkVersion() {
    m_statusLabel->setText("Checking version...");
    m_versionText->setPlainText("Please wait while checking version...");
    m_updateButton->setEnabled(false);
    m_checkButton->setEnabled(false);

    // Let GUI update
    QApplication::processEvents();

    QString fearPath = m_cliPath;
    if (fearPath.isEmpty() || !QFile::exists(fearPath)) {
#ifdef Q_OS_WIN
        fearPath = "./bin/fear.exe";
        if (!QFile::exists(fearPath)) {
            fearPath = "fear.exe";
        }
#else
        fearPath = "./bin/fear";
        if (!QFile::exists(fearPath)) {
            fearPath = "fear";
        }
#endif
    }

    if (!QFile::exists(fearPath)) {
#ifdef Q_OS_WIN
        m_versionText->setPlainText("Error: fear.exe not found!\n"
                                    "Searched paths:\n"
                                    "- " + m_cliPath + "\n"
                                    "- ./bin/fear.exe\n"
                                    "- fear.exe\n\n"
                                    "Please set the correct CLI path in File -> Set CLI path...");
        m_statusLabel->setText("Error: fear.exe not found");
#else
        m_versionText->setPlainText("Error: fear not found!\n"
                                    "Searched paths:\n"
                                    "- " + m_cliPath + "\n"
                                    "- ./bin/fear\n"
                                    "- fear\n\n"
                                    "Please set the correct CLI path in File -> Set CLI path...");
        m_statusLabel->setText("Error: fear not found");
#endif
        m_checkButton->setEnabled(true);
        return;
    }

    QProcess *process = new QProcess(this);
    process->start(fearPath, QStringList() << "--version");

    if (!process->waitForStarted(3000)) {
        m_versionText->setPlainText("Error: Failed to start fear process\n"
                                    "Path: " + fearPath);
        m_statusLabel->setText("Error: Process failed to start");
        process->deleteLater();
        m_checkButton->setEnabled(true);
        return;
    }

    if (!process->waitForFinished(10000)) {
        m_versionText->setPlainText("Error: Process timed out after 10 seconds");
        m_statusLabel->setText("Error: Process timed out");
        process->kill();
        process->waitForFinished(1000);
        process->deleteLater();
        m_checkButton->setEnabled(true);
        return;
    }

    QString output = QString::fromUtf8(process->readAllStandardOutput());
    QString error = QString::fromUtf8(process->readAllStandardError());

    if (process->exitCode() != 0) {
        m_versionText->setPlainText(QString("Error: Process exited with code %1\n\nError output:\n%2\n\nStandard output:\n%3")
                                        .arg(process->exitCode()).arg(error).arg(output));
        m_statusLabel->setText("Error: Process failed");
        process->deleteLater();
        m_checkButton->setEnabled(true);
        return;
    }

    // Parse version
    QString currentVersion = parseVersion(output);
    m_currentVersion = currentVersion;

    QString versionInfo = QString("Current F.E.A.R. version: %1\n\nFull output:\n%2")
                              .arg(currentVersion.isEmpty() ? "Unknown" : currentVersion)
                              .arg(output);

    m_versionText->setPlainText(versionInfo);

    // Enable update button
    m_updateButton->setEnabled(true);
    m_checkButton->setEnabled(true);
    m_statusLabel->setText(currentVersion.isEmpty() ? "Version unknown" : "Version: " + currentVersion);

    process->deleteLater();
}

void UpdateDialog::runUpdater() {
#ifdef Q_OS_WIN
    QString updaterPath = "./bin/updater.exe";
#else
    QString updaterPath = "./bin/updater";
#endif
    QFileInfo updaterInfo(updaterPath);

    if (!updaterInfo.exists()) {
        QMessageBox::warning(this, "Update Error",
                             "Updater not found at: " + updaterPath +
                             "\nPlease download the updater manually from GitHub.");
        return;
    }

    // Get absolute path to updater.exe directory
    QString updaterDir = updaterInfo.absolutePath();

    if (QMessageBox::question(this, "Confirm Update",
                              "The updater will now start. This may take several minutes.\n"
                              "Do you want to continue?") != QMessageBox::Yes) {
        return;
    }

    // Disable buttons during update
    m_updateButton->setEnabled(false);
    m_checkButton->setEnabled(false);
    m_statusLabel->setText("Running updater...");

    // Clear text field and show updater output
    m_versionText->clear();
    m_versionText->setPlainText("Starting updater...\n\n");

    // Create process for updater
    m_updaterProcess = new QProcess(this);
    m_updaterProcess->setWorkingDirectory(updaterDir);
    m_updaterProcess->setProcessChannelMode(QProcess::MergedChannels);

    // Connect signals for reading output
    connect(m_updaterProcess, &QProcess::readyRead, this, &UpdateDialog::onUpdaterOutput);
    connect(m_updaterProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &UpdateDialog::onUpdaterFinished);

    // Start process
    m_updaterProcess->start(updaterInfo.absoluteFilePath());

    if (!m_updaterProcess->waitForStarted(3000)) {
        m_versionText->append("Error: Failed to start updater process");
        m_statusLabel->setText("Error: Updater failed to start");
        cleanupUpdaterProcess();
        return;
    }

    m_versionText->append("Updater started successfully. Waiting for output...\n");
}

void UpdateDialog::onUpdaterOutput() {
    if (!m_updaterProcess) return;

    QByteArray output = m_updaterProcess->readAll();
    QString text = QString::fromUtf8(output);

    // Add output to text field
    m_versionText->insertPlainText(text);

    // Scroll down
    QTextCursor cursor = m_versionText->textCursor();
    cursor.movePosition(QTextCursor::End);
    m_versionText->setTextCursor(cursor);

    // Process output
    QApplication::processEvents();
}

void UpdateDialog::onUpdaterFinished(int exitCode, QProcess::ExitStatus exitStatus) {
    Q_UNUSED(exitStatus);

    m_versionText->append(QString("\n\nUpdater finished with exit code: %1").arg(exitCode));

    if (exitCode == 0) {
        m_versionText->append("Update completed successfully!");
        m_statusLabel->setText("Update completed");

        // Automatic restart with confirmation
        m_versionText->append("Update completed! The application needs to restart to apply changes.");
        QApplication::processEvents();

        if (QMessageBox::information(this, "Update Complete",
                                     "Update completed successfully!\n"
                                     "The application will now restart to apply the changes.",
                                     QMessageBox::Ok) == QMessageBox::Ok) {
            restartApplication();
        } else {
            cleanupUpdaterProcess();
        }

    } else {
        m_versionText->append("Update failed or was cancelled.");
        m_statusLabel->setText("Update failed");

        QMessageBox::warning(this, "Update Failed",
                             QString("Updater exited with code %1. Please check the output above for details.")
                             .arg(exitCode));

        cleanupUpdaterProcess();
    }
}

void UpdateDialog::restartApplication() {
    qDebug() << "Restarting application...";

    // Get path to current executable
    QString program = QApplication::applicationFilePath();
    QStringList arguments = QApplication::arguments();
    QString workingDir = QApplication::applicationDirPath();

    // Remove possible duplicate arguments
    if (!arguments.isEmpty() && arguments.first() == program) {
        arguments.removeFirst();
    }

    // Start new copy of application
    bool started = QProcess::startDetached(program, arguments, workingDir);

    if (started) {
        qDebug() << "New instance started successfully, closing current instance";
        QApplication::quit();
    } else {
        qDebug() << "Failed to restart application";
        QMessageBox::warning(this, "Restart Failed",
                             "Failed to restart the application. Please restart it manually.");
        cleanupUpdaterProcess();
    }
}

void UpdateDialog::cleanupUpdaterProcess() {
    if (m_updaterProcess) {
        if (m_updaterProcess->state() == QProcess::Running) {
            m_updaterProcess->kill();
            m_updaterProcess->waitForFinished(1000);
        }
        m_updaterProcess->deleteLater();
        m_updaterProcess = nullptr;
    }
    m_updateButton->setEnabled(true);
    m_checkButton->setEnabled(true);
}

QString UpdateDialog::parseVersion(const QString &output) {
    // Look for program version string
    QRegularExpression re("Program version:\\s*([0-9]+\\.[0-9]+\\.[0-9]+)");
    QRegularExpressionMatch match = re.match(output);

    if (match.hasMatch()) {
        return match.captured(1).trimmed();
    }

    // Alternative formats
    re.setPattern("version\\s*([0-9]+\\.[0-9]+\\.[0-9]+)");
    match = re.match(output);

    if (match.hasMatch()) {
        return match.captured(1).trimmed();
    }

    re.setPattern("([0-9]+\\.[0-9]+\\.[0-9]+)");
    match = re.match(output);

    if (match.hasMatch()) {
        return match.captured(1).trimmed();
    }

    return QString();
}
