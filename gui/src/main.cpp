/**
 * @file main.cpp
 * @brief Main entry point for F.E.A.R. GUI application
 *
 * This file contains only the main() function that initializes
 * the Qt application and shows the main window.
 */

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

    /*
     * Окно теперь одно.
     *
     * Старое (MainWindow) держали за ключом --classic-ui на время перехода,
     * и держали слишком долго: два окна - это два места, где чинить каждую
     * ошибку, и два набора возможностей, расходящихся тем сильнее, чем
     * дольше живут оба. Всё, что было только в старом, - свой ретранслятор,
     * ручной обмен ключами, выбор шрифта, ссылка на руководство и значок в
     * лотке - перенесено в новое, а не выброшено вместе с окном.
     */
    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addVersionOption();
    parser.process(app);

    fear::ChatWindow w;
    w.show();
    return app.exec();
}
