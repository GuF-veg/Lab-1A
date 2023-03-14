#include <QApplication>
#include <QStyleFactory>
#include "mainwindow.h"

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    QApplication::setStyle(QStyleFactory::create("Fusion"));
    MainWindow *wd = new MainWindow;
    wd->show();
    return QApplication::exec();
}
