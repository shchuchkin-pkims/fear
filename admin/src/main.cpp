/**
 * @file main.cpp
 * @brief Утилита администрирования ретранслятора F.E.A.R.
 *
 * Работает с базой на той же машине, где живёт сервер: открывает тот же файл
 * SQLite, а не копию. Сеть тут ни при чём - у сервера нет и не появилось
 * команд администрирования, а значит нет и новой поверхности атаки на
 * машине, через которую ходит чужая переписка.
 *
 * Путь к базе берётся из аргумента, затем из FEAR_SERVER_DB, затем
 * ./fear-server.sqlite - тот же порядок, что и у самого сервера, чтобы
 * запуск из его рабочего каталога просто работал.
 */
#include <QApplication>
#include <QFile>

#include "adminwindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("fear-admin"));
    QApplication::setOrganizationName(QStringLiteral("F.E.A.R."));

    QString path;
    if (argc > 1) {
        path = QString::fromLocal8Bit(argv[1]);
    } else if (qEnvironmentVariableIsSet("FEAR_SERVER_DB")) {
        path = qEnvironmentVariable("FEAR_SERVER_DB");
    } else if (QFile::exists(QStringLiteral("./fear-server.sqlite"))) {
        path = QStringLiteral("./fear-server.sqlite");
    }

    AdminWindow w;
    w.show();
    /* Ничего не нашли - окно открывается пустым, и «База -> Открыть» на виду.
     * Диалог поверх пустого окна на старте выглядел бы как ошибка, а её тут
     * нет: путь просто не задан. */
    if (!path.isEmpty()) w.openDatabase(path);

    return app.exec();
}
