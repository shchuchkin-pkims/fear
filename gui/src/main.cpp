/**
 * @file main.cpp
 * @brief Main entry point for F.E.A.R. GUI application
 *
 * This file contains only the main() function that initializes
 * the Qt application and shows the main window.
 */

#include "mainwindow.h"
#include "chatwindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QIcon>
#include <QFile>
#include <QDir>
#include <QDebug>

/**
 * @brief Clean up old backup files from previous updates
 *
 * After an update, the updater may leave .old files that were locked.
 * This function removes them on startup.
 */
static void cleanupOldFiles() {
#ifdef Q_OS_WIN
    // Look for fear_gui.exe.old in the same directory as the executable
    QString appDir = QCoreApplication::applicationDirPath();
    QString oldGuiPath = appDir + "/fear_gui.exe.old";

    if (QFile::exists(oldGuiPath)) {
        qDebug() << "Found old backup file, attempting to remove:" << oldGuiPath;
        if (QFile::remove(oldGuiPath)) {
            qDebug() << "Successfully removed old backup file";
        } else {
            qDebug() << "Warning: Could not remove old backup file (may still be in use)";
        }
    }

    // Also check parent directory (in case we're in a subdirectory)
    QDir parentDir(appDir);
    if (parentDir.cdUp()) {
        QString oldGuiParentPath = parentDir.absolutePath() + "/fear_gui.exe.old";
        if (QFile::exists(oldGuiParentPath)) {
            qDebug() << "Found old backup file in parent dir, attempting to remove:" << oldGuiParentPath;
            if (QFile::remove(oldGuiParentPath)) {
                qDebug() << "Successfully removed old backup file from parent directory";
            } else {
                qDebug() << "Warning: Could not remove old backup file from parent directory";
            }
        }
    }
#endif
}

/**
 * @brief Main application entry point
 * @param argc Argument count
 * @param argv Argument values
 * @return Application exit code
 */
int main(int argc, char **argv) {
    // Opt out of X11 session management to avoid libICE killing us via its
    // default IO error handler when the SM socket goes away mid-session.
    // We don't participate in OS save/restore flows.
    qunsetenv("SESSION_MANAGER");

    QApplication app(argc, argv);

    // Set application metadata for proper desktop integration
    app.setApplicationName("F.E.A.R.");
    app.setApplicationDisplayName("F.E.A.R.");
    app.setOrganizationName("F.E.A.R.");
    app.setDesktopFileName("fear_gui");

    // Use PNG icon for Linux, ICO for Windows
#ifdef Q_OS_WIN
    app.setWindowIcon(QIcon(":/icons/logo.ico"));
#else
    app.setWindowIcon(QIcon(":/icons/logo.png"));
#endif

    // Clean up old backup files from previous updates
    cleanupOldFiles();

    // Parse CLI: --classic-ui falls back to legacy MainWindow during transition
    QCommandLineParser parser;
    QCommandLineOption classicUi(QStringList() << "classic-ui",
        QStringLiteral("Use legacy GUI instead of the new Telegram-style window."));
    parser.addOption(classicUi);
    parser.addHelpOption();
    parser.process(app);

    if (parser.isSet(classicUi)) {
        MainWindow w;
        w.show();
        return app.exec();
    }

    fear::ChatWindow w;
    w.show();
    return app.exec();
}
