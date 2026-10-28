/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef KEEPASSXC_WINDOWSPASSKEYSERVICE_H
#define KEEPASSXC_WINDOWSPASSKEYSERVICE_H

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QMap>
#include <QObject>
#include <QPointer>

class QLocalServer;
class QLocalSocket;
class MainWindow;
class Database;
class Entry;

class WindowsPasskeyService : public QObject
{
    Q_OBJECT

public:
    explicit WindowsPasskeyService(QObject* parent = nullptr);
    ~WindowsPasskeyService() override;

    static WindowsPasskeyService* instance();

    void init(MainWindow* mainWindow);
    void start();
    void stop();

    void notifyCredentialsChanged();

private slots:
    void onNewConnection();
    void onSocketReadyRead();
    void onSocketDisconnected();

private:
    void processRequest(QLocalSocket* socket, const QJsonObject& request);
    void sendResponse(QLocalSocket* socket, const QJsonObject& response);
    void sendError(QLocalSocket* socket, const QString& type, const QString& errorCode, const QString& errorMessage);

    QJsonObject handlePing(const QJsonObject& req);
    QJsonObject handleGetCredentials(const QJsonObject& req);
    QJsonObject handleGetDatabases(const QJsonObject& req);
    QJsonObject handleFindMatchingEntries(const QJsonObject& req);
    QJsonObject handleMakeCredential(const QJsonObject& req);
    QJsonObject handleGetAssertion(const QJsonObject& req);
    QJsonObject handleUnlockDatabase(const QJsonObject& req);
    QJsonObject handleGetSettings(const QJsonObject& req);
    QJsonObject handleSaveSettings(const QJsonObject& req);

    static QString getCurrentUserSid();
    QList<Database*> openDatabases() const;

    bool generateKeyPair(int alg, QByteArray& outCoseKey, QString& outPrivateKeyPem);
    QByteArray signData(const QString& privateKeyPem, const QByteArray& dataToSign);
    QString entryIconBase64(Entry* entry);

    void initSettings();
    void saveSettingsToDisk();

    QPointer<MainWindow> m_mainWindow;
    QList<QLocalServer*> m_servers;
    QMap<QLocalSocket*, QByteArray> m_clientBuffers;

    QString m_userSid;
    bool m_running = false;
    QJsonObject m_settings;
};

static inline WindowsPasskeyService* windowsPasskeyService()
{
    return WindowsPasskeyService::instance();
}

#endif // KEEPASSXC_WINDOWSPASSKEYSERVICE_H
