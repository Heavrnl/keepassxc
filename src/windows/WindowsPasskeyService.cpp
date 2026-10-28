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

#include "WindowsPasskeyService.h"

#include "browser/BrowserCbor.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntryAttributes.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "core/Tools.h"
#include "crypto/CryptoHash.h"
#include "crypto/Random.h"
#include "gui/DatabaseIcons.h"
#include "gui/DatabaseTabWidget.h"
#include "gui/DatabaseWidget.h"
#include "gui/Icons.h"
#include "gui/MainWindow.h"

#include <QBuffer>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPainter>
#include <QProcess>
#include <QSettings>
#include <QStandardPaths>
#include <QtEndian>

#include <windows.h>
#include <sddl.h>

#include <botan/bigint.h>
#include <botan/data_src.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/ed25519.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>

Q_GLOBAL_STATIC(WindowsPasskeyService, s_windowsPasskeyService)

namespace {
    static QByteArray bigIntToQByteArray(Botan::BigInt& bigInt)
    {
        std::vector<uint8_t> bytes(bigInt.bytes());
        bigInt.binary_encode(bytes.data());
        QByteArray result(reinterpret_cast<const char*>(bytes.data()), static_cast<qsizetype>(bytes.size()));
        while (result.size() < 32) {
            result.prepend('\0');
        }
        return result;
    }
}

WindowsPasskeyService* WindowsPasskeyService::instance()
{
    return s_windowsPasskeyService;
}

WindowsPasskeyService::WindowsPasskeyService(QObject* parent)
    : QObject(parent)
{
    m_userSid = getCurrentUserSid();
    initSettings();
}

WindowsPasskeyService::~WindowsPasskeyService()
{
    stop();
}

void WindowsPasskeyService::init(MainWindow* mainWindow)
{
    m_mainWindow = mainWindow;
}

QString WindowsPasskeyService::getCurrentUserSid()
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return {};
    }

    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return {};
    }

    QByteArray buffer(static_cast<int>(len), 0);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), len, &len)) {
        CloseHandle(hToken);
        return {};
    }

    auto* pTokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPSTR sidString = nullptr;
    QString result;
    if (ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
        result = QString::fromLatin1(sidString);
        LocalFree(sidString);
    }
    CloseHandle(hToken);
    return result;
}

void WindowsPasskeyService::start()
{
    if (m_running) {
        return;
    }

    QStringList pipeNames;
    if (!m_userSid.isEmpty()) {
        pipeNames << QStringLiteral("keepass-passkey-provider-%1").arg(m_userSid);
        pipeNames << QStringLiteral("keepass-passkey-provider-dev-%1").arg(m_userSid);
    }
    pipeNames << QStringLiteral("keepass-passkey-provider");

    for (const auto& name : pipeNames) {
        auto* server = new QLocalServer(this);
        server->setSocketOptions(QLocalServer::WorldAccessOption);
        QLocalServer::removeServer(name);
        if (server->listen(name)) {
            connect(server, &QLocalServer::newConnection, this, &WindowsPasskeyService::onNewConnection);
            m_servers.append(server);
        } else {
            qWarning() << "WindowsPasskeyService: Failed to listen on pipe:" << name << server->errorString();
            delete server;
        }
    }

    m_running = !m_servers.isEmpty();
}

void WindowsPasskeyService::stop()
{
    for (auto* server : m_servers) {
        server->close();
        delete server;
    }
    m_servers.clear();
    m_clientBuffers.clear();
    m_running = false;
}

void WindowsPasskeyService::onNewConnection()
{
    auto* server = qobject_cast<QLocalServer*>(sender());
    if (!server) {
        return;
    }

    while (server->hasPendingConnections()) {
        auto* socket = server->nextPendingConnection();
        if (!socket) {
            break;
        }
        connect(socket, &QLocalSocket::readyRead, this, &WindowsPasskeyService::onSocketReadyRead);
        connect(socket, &QLocalSocket::disconnected, this, &WindowsPasskeyService::onSocketDisconnected);
        m_clientBuffers[socket] = QByteArray();
    }
}

void WindowsPasskeyService::onSocketDisconnected()
{
    auto* socket = qobject_cast<QLocalSocket*>(sender());
    if (socket) {
        m_clientBuffers.remove(socket);
        socket->deleteLater();
    }
}

void WindowsPasskeyService::onSocketReadyRead()
{
    auto* socket = qobject_cast<QLocalSocket*>(sender());
    if (!socket) {
        return;
    }

    auto& buf = m_clientBuffers[socket];
    buf.append(socket->readAll());

    while (buf.size() >= 4) {
        quint32 payloadLength = qFromLittleEndian<quint32>(reinterpret_cast<const uchar*>(buf.constData()));
        if (static_cast<quint32>(buf.size()) < 4 + payloadLength) {
            break;
        }

        QByteArray jsonBytes = buf.mid(4, payloadLength);
        buf.remove(0, 4 + payloadLength);

        QJsonParseError parseError;
        QJsonDocument doc = QJsonDocument::fromJson(jsonBytes, &parseError);
        if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
            processRequest(socket, doc.object());
        } else {
            qWarning() << "WindowsPasskeyService: Malformed JSON received:" << parseError.errorString();
        }
    }
}

void WindowsPasskeyService::sendResponse(QLocalSocket* socket, const QJsonObject& response)
{
    if (!socket || socket->state() != QLocalSocket::ConnectedState) {
        return;
    }

    QByteArray jsonBytes = QJsonDocument(response).toJson(QJsonDocument::Compact);
    quint32 length = static_cast<quint32>(jsonBytes.size());

    QByteArray frame;
    frame.resize(4);
    qToLittleEndian<quint32>(length, reinterpret_cast<uchar*>(frame.data()));
    frame.append(jsonBytes);

    socket->write(frame);
    socket->flush();
}

void WindowsPasskeyService::sendError(QLocalSocket* socket,
                                     const QString& type,
                                     const QString& errorCode,
                                     const QString& errorMessage)
{
    QJsonObject obj;
    obj["type"] = type;
    obj["errorCode"] = errorCode;
    obj["errorMessage"] = errorMessage;
    sendResponse(socket, obj);
}

QList<Database*> WindowsPasskeyService::openDatabases() const
{
    QList<Database*> result;
    if (!m_mainWindow) {
        return result;
    }

    auto* tabWidget = m_mainWindow->findChild<DatabaseTabWidget*>();
    if (!tabWidget) {
        return result;
    }

    for (int i = 0; i < tabWidget->count(); ++i) {
        auto* dbWidget = tabWidget->databaseWidgetFromIndex(i);
        if (dbWidget && !dbWidget->isLocked() && dbWidget->database()) {
            result.append(dbWidget->database().data());
        }
    }
    return result;
}

void WindowsPasskeyService::processRequest(QLocalSocket* socket, const QJsonObject& req)
{
    const QString type = req.value("type").toString();
    QJsonObject reply;

    if (type == QStringLiteral("ping")) {
        reply = handlePing(req);
    } else if (type == QStringLiteral("get_credentials")) {
        reply = handleGetCredentials(req);
    } else if (type == QStringLiteral("get_databases")) {
        reply = handleGetDatabases(req);
    } else if (type == QStringLiteral("find_matching_entries")) {
        reply = handleFindMatchingEntries(req);
    } else if (type == QStringLiteral("make_credential")) {
        reply = handleMakeCredential(req);
    } else if (type == QStringLiteral("get_assertion")) {
        reply = handleGetAssertion(req);
    } else if (type == QStringLiteral("unlock_database")) {
        reply = handleUnlockDatabase(req);
    } else if (type == QStringLiteral("get_settings")) {
        reply = handleGetSettings(req);
    } else if (type == QStringLiteral("save_settings")) {
        reply = handleSaveSettings(req);
    } else {
        reply["type"] = type;
        reply["errorCode"] = "internal_error";
        reply["errorMessage"] = QString("Unknown request type: %1").arg(type);
    }

    sendResponse(socket, reply);
}

QJsonObject WindowsPasskeyService::handlePing(const QJsonObject& req)
{
    QJsonObject reply;
    reply["type"] = "ping";
    reply["protocolVersion"] = 1;
    reply["version"] = QStringLiteral("2.8.0-Snapshot");
    reply["pluginPath"] = QStringLiteral("builtin:KeePassXC");

    int proto = req.value("protocolVersion").toInt(1);
    if (proto != 1) {
        reply["status"] = "incompatible_version";
    } else {
        bool hasOpen = !openDatabases().isEmpty();
        reply["status"] = hasOpen ? "ready" : "no_database";
    }

    return reply;
}

QJsonObject WindowsPasskeyService::handleGetCredentials(const QJsonObject& req)
{
    QJsonObject reply;
    reply["type"] = "get_credentials";

    auto dbs = openDatabases();
    if (dbs.isEmpty()) {
        reply["errorCode"] = "db_locked";
        reply["errorMessage"] = "No database open";
        return reply;
    }

    QString filterRpId = req.value("rpId").toString();
    QJsonArray allowCredentials = req.value("allowCredentials").toArray();
    QSet<QString> allowSet;
    for (const auto& v : allowCredentials) {
        allowSet.insert(v.toString());
    }
    bool omitIcons = req.value("omitIcons").toBool();

    QJsonArray credsArray;
    bool nameDatabases = dbs.size() > 1;

    for (auto* db : dbs) {
        QString dbName = db->metadata()->name();
        if (dbName.isEmpty() && !db->filePath().isEmpty()) {
            dbName = QFileInfo(db->filePath()).fileName();
        }
        if (dbName.isEmpty()) {
            dbName = QStringLiteral("(unnamed)");
        }

        const auto entries = db->rootGroup()->entriesRecursive(false);
        for (auto* entry : entries) {
            if (entry->isRecycled() || !entry->hasPasskey()) {
                continue;
            }

            auto* attrs = entry->attributes();
            QString credId = attrs->value(EntryAttributes::KPEX_PASSKEY_CREDENTIAL_ID);
            QString rpId = attrs->value(EntryAttributes::KPEX_PASSKEY_RELYING_PARTY);

            if (!filterRpId.isEmpty() && rpId != filterRpId) {
                continue;
            }
            if (!allowSet.isEmpty() && !allowSet.contains(credId)) {
                continue;
            }

            QJsonObject credObj;
            credObj["credentialId"] = credId;
            credObj["rpId"] = rpId;
            credObj["userHandle"] = attrs->value(EntryAttributes::KPEX_PASSKEY_USER_HANDLE);

            QString userName = attrs->value(EntryAttributes::KPEX_PASSKEY_USERNAME);
            if (userName.isEmpty()) {
                userName = entry->username();
            }
            credObj["userName"] = userName;
            credObj["title"] = entry->title();

            if (nameDatabases) {
                credObj["databaseName"] = dbName;
            }
            if (!omitIcons) {
                credObj["icon"] = entryIconBase64(entry);
            }

            credsArray.append(credObj);
        }
    }

    reply["credentials"] = credsArray;
    return reply;
}

QJsonObject WindowsPasskeyService::handleGetDatabases(const QJsonObject&)
{
    QJsonObject reply;
    reply["type"] = "get_databases";

    QJsonArray dbsArray;
    for (auto* db : openDatabases()) {
        QJsonObject dbObj;
        dbObj["id"] = Tools::uuidToHex(db->rootGroup()->uuid());
        QString name = db->metadata()->name();
        if (name.isEmpty() && !db->filePath().isEmpty()) {
            name = QFileInfo(db->filePath()).fileName();
        }
        dbObj["name"] = name.isEmpty() ? QStringLiteral("(unnamed)") : name;
        dbsArray.append(dbObj);
    }

    reply["databases"] = dbsArray;
    return reply;
}

QJsonObject WindowsPasskeyService::handleFindMatchingEntries(const QJsonObject& req)
{
    QJsonObject reply;
    reply["type"] = "find_matching_entries";

    auto dbs = openDatabases();
    if (dbs.isEmpty()) {
        reply["errorCode"] = "db_locked";
        reply["errorMessage"] = "No database open";
        return reply;
    }

    QString rpId = req.value("rpId").toString();
    if (rpId.isEmpty()) {
        reply["errorCode"] = "internal_error";
        reply["errorMessage"] = "rpId is required";
        return reply;
    }

    QJsonArray matches;
    for (auto* db : dbs) {
        QString dbId = Tools::uuidToHex(db->rootGroup()->uuid());
        QString dbName = db->metadata()->name();
        if (dbName.isEmpty()) {
            dbName = QStringLiteral("(unnamed)");
        }

        const auto entries = db->rootGroup()->entriesRecursive(false);
        for (auto* entry : entries) {
            if (entry->isRecycled()) {
                continue;
            }
            bool match = false;
            auto* attrs = entry->attributes();
            if (attrs->value(EntryAttributes::KPEX_PASSKEY_RELYING_PARTY) == rpId) {
                match = true;
            } else {
                QString url = entry->url();
                if (!url.isEmpty() && (url.contains(rpId, Qt::CaseInsensitive) || rpId.contains(url, Qt::CaseInsensitive))) {
                    match = true;
                } else if (entry->title().contains(rpId, Qt::CaseInsensitive)) {
                    match = true;
                }
            }

            if (match) {
                QJsonObject matchObj;
                matchObj["entryUuid"] = Tools::uuidToHex(entry->uuid());
                matchObj["databaseId"] = dbId;
                matchObj["databaseName"] = dbName;
                matchObj["title"] = entry->title();
                matchObj["hasPasskey"] = entry->hasPasskey();
                matchObj["isSelected"] = false;
                matchObj["userName"] = entry->username();
                matchObj["icon"] = entryIconBase64(entry);
                matches.append(matchObj);
            }
        }
    }

    reply["entries"] = matches;
    return reply;
}

QJsonObject WindowsPasskeyService::handleMakeCredential(const QJsonObject& req)
{
    QJsonObject reply;
    reply["type"] = "make_credential";

    auto dbs = openDatabases();
    if (dbs.isEmpty()) {
        reply["errorCode"] = "db_locked";
        reply["errorMessage"] = "No database open";
        return reply;
    }

    QString rpId = req.value("rpId").toString();
    if (rpId.isEmpty()) {
        reply["errorCode"] = "internal_error";
        reply["errorMessage"] = "rpId is required";
        return reply;
    }

    // Check excludeCredentials
    QJsonArray excludeCredentials = req.value("excludeCredentials").toArray();
    QSet<QString> excludeSet;
    for (const auto& v : excludeCredentials) {
        excludeSet.insert(v.toString());
    }

    if (!excludeSet.isEmpty()) {
        for (auto* db : dbs) {
            const auto entries = db->rootGroup()->entriesRecursive(false);
            for (auto* entry : entries) {
                if (entry->isRecycled() || !entry->hasPasskey()) continue;
                auto* attrs = entry->attributes();
                if (attrs->value(EntryAttributes::KPEX_PASSKEY_RELYING_PARTY) == rpId
                    && excludeSet.contains(attrs->value(EntryAttributes::KPEX_PASSKEY_CREDENTIAL_ID))) {
                    reply["errorCode"] = "duplicate";
                    reply["errorMessage"] = "Credential already exists for this RP";
                    return reply;
                }
            }
        }
    }

    // Algorithm selection: ES256 (-7) > EdDSA (-8) > RS256 (-257)
    int chosenAlg = -7;
    QJsonArray credParams = req.value("pubKeyCredParams").toArray();
    if (!credParams.isEmpty()) {
        QList<int> supportedAlgs = {-7, -8, -257};
        bool found = false;
        for (const auto& p : credParams) {
            int alg = p.toInt();
            if (supportedAlgs.contains(alg)) {
                chosenAlg = alg;
                found = true;
                break;
            }
        }
        if (!found) {
            reply["errorCode"] = "unsupported_algorithm";
            reply["errorMessage"] = "No supported algorithm in pubKeyCredParams";
            return reply;
        }
    }

    QByteArray coseKeyBytes;
    QString privateKeyPem;
    if (!generateKeyPair(chosenAlg, coseKeyBytes, privateKeyPem)) {
        reply["errorCode"] = "internal_error";
        reply["errorMessage"] = "Failed to generate key pair";
        return reply;
    }

    // Generate 32-byte random credential ID, base64url encoded
    QByteArray credIdRaw = randomGen()->randomArray(32);
    QString credentialId = QString::fromLatin1(credIdRaw.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    QString coseKeyB64Url = QString::fromLatin1(coseKeyBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));

    // Target database & entry
    Database* targetDb = dbs.first();
    QJsonObject targetDbObj = req.value("targetDatabase").toObject();
    if (!targetDbObj.isEmpty()) {
        QString dbId = targetDbObj.value("id").toString();
        for (auto* db : dbs) {
            if (Tools::uuidToHex(db->rootGroup()->uuid()).compare(dbId, Qt::CaseInsensitive) == 0) {
                targetDb = db;
                break;
            }
        }
    }

    Entry* targetEntry = nullptr;
    QJsonObject targetEntryObj = req.value("targetEntry").toObject();
    if (!targetEntryObj.isEmpty()) {
        QString entryUuidHex = targetEntryObj.value("entryUuid").toString();
        const auto entries = targetDb->rootGroup()->entriesRecursive(false);
        for (auto* e : entries) {
            if (e->isRecycled()) continue;
            if (Tools::uuidToHex(e->uuid()).compare(entryUuidHex, Qt::CaseInsensitive) == 0) {
                targetEntry = e;
                break;
            }
        }
    }

    QString rpName = req.value("rpName").toString();
    QString userId = req.value("userId").toString();
    QString userName = req.value("userName").toString();

    if (!targetEntry) {
        // Create new entry
        targetEntry = new Entry();
        targetEntry->setUuid(QUuid::createUuid());
        targetEntry->setTitle(rpName.isEmpty() ? rpId : rpName);
        targetEntry->setUsername(userName);
        targetEntry->setUrl(QString("https://%1").arg(rpId));

        Group* targetGroup = targetDb->rootGroup();
        for (auto* g : targetDb->rootGroup()->children()) {
            if (g->name().compare(QStringLiteral("Passkeys"), Qt::CaseInsensitive) == 0 && !g->isRecycled()) {
                targetGroup = g;
                break;
            }
        }
        targetEntry->setGroup(targetGroup);
    }

    auto* attrs = targetEntry->attributes();
    attrs->set(EntryAttributes::KPEX_PASSKEY_CREDENTIAL_ID, credentialId, true);
    attrs->set(EntryAttributes::KPEX_PASSKEY_PRIVATE_KEY_PEM, privateKeyPem, true);
    attrs->set(EntryAttributes::KPEX_PASSKEY_RELYING_PARTY, rpId);
    attrs->set(EntryAttributes::KPEX_PASSKEY_USER_HANDLE, userId, true);
    attrs->set(EntryAttributes::KPEX_PASSKEY_USERNAME, userName);
    attrs->set(EntryAttributes::KPEX_PASSKEY_FLAG_BE, "1");
    attrs->set(EntryAttributes::KPEX_PASSKEY_FLAG_BS, "1");

    if (!targetEntry->tags().contains(tr("Passkey"))) {
        targetEntry->addTag(tr("Passkey"));
    }

    reply["credentialId"] = credentialId;
    reply["coseKey"] = coseKeyB64Url;
    reply["backupEligible"] = true;
    reply["backupState"] = true;

    notifyCredentialsChanged();
    return reply;
}

QJsonObject WindowsPasskeyService::handleGetAssertion(const QJsonObject& req)
{
    QJsonObject reply;
    reply["type"] = "get_assertion";

    auto dbs = openDatabases();
    if (dbs.isEmpty()) {
        reply["errorCode"] = "db_locked";
        reply["errorMessage"] = "No database open";
        return reply;
    }

    QString rpId = req.value("rpId").toString();
    if (rpId.isEmpty()) {
        reply["errorCode"] = "internal_error";
        reply["errorMessage"] = "rpId is required";
        return reply;
    }

    QString clientDataHashB64 = req.value("clientDataHash").toString();
    if (clientDataHashB64.isEmpty()) {
        reply["errorCode"] = "internal_error";
        reply["errorMessage"] = "clientDataHash is required";
        return reply;
    }
    QByteArray clientDataHash = QByteArray::fromBase64(clientDataHashB64.toLatin1());

    QJsonArray allowCreds = req.value("allowCredentials").toArray();
    QSet<QString> allowSet;
    for (const auto& v : allowCreds) {
        allowSet.insert(v.toString());
    }

    Entry* matchedEntry = nullptr;
    for (auto* db : dbs) {
        const auto entries = db->rootGroup()->entriesRecursive(false);
        for (auto* entry : entries) {
            if (entry->isRecycled() || !entry->hasPasskey()) continue;
            auto* attrs = entry->attributes();
            if (attrs->value(EntryAttributes::KPEX_PASSKEY_RELYING_PARTY) == rpId) {
                QString credId = attrs->value(EntryAttributes::KPEX_PASSKEY_CREDENTIAL_ID);
                if (allowSet.isEmpty() || allowSet.contains(credId)) {
                    matchedEntry = entry;
                    break;
                }
            }
        }
        if (matchedEntry) break;
    }

    if (!matchedEntry) {
        reply["errorCode"] = "not_found";
        reply["errorMessage"] = QString("No matching credential found for rpId: %1").arg(rpId);
        return reply;
    }

    auto* attrs = matchedEntry->attributes();
    QString credentialId = attrs->value(EntryAttributes::KPEX_PASSKEY_CREDENTIAL_ID);
    QString privateKeyPem = attrs->value(EntryAttributes::KPEX_PASSKEY_PRIVATE_KEY_PEM);
    QString userHandle = attrs->value(EntryAttributes::KPEX_PASSKEY_USER_HANDLE);
    QString userName = attrs->value(EntryAttributes::KPEX_PASSKEY_USERNAME);
    if (userName.isEmpty()) {
        userName = matchedEntry->username();
    }

    bool beFlag = attrs->value(EntryAttributes::KPEX_PASSKEY_FLAG_BE) == "1";
    bool bsFlag = attrs->value(EntryAttributes::KPEX_PASSKEY_FLAG_BS) == "1";

    // Build 37-byte authenticatorData
    // [0..31]: rpIdHash (SHA-256 of rpId)
    // [32]: flags: UP (0x01) | UV (0x04) | BE (0x08) | BS (0x10)
    // [33..36]: signCount (0x00 0x00 0x00 0x00)
    QByteArray authData;
    QByteArray rpIdHash = CryptoHash::hash(rpId.toUtf8(), CryptoHash::Sha256);
    authData.append(rpIdHash);

    char flags = 0x01 | 0x04; // UP | UV
    if (beFlag) flags |= 0x08;
    if (bsFlag) flags |= 0x10;
    authData.append(flags);

    const char counter[4] = {0, 0, 0, 0};
    authData.append(counter, 4);

    QByteArray dataToSign = authData + clientDataHash;
    QByteArray signature = signData(privateKeyPem, dataToSign);

    if (signature.isEmpty()) {
        reply["errorCode"] = "internal_error";
        reply["errorMessage"] = "Signature generation failed";
        return reply;
    }

    reply["credentialId"] = credentialId;
    reply["authenticatorData"] = QString::fromLatin1(authData.toBase64());
    reply["signature"] = QString::fromLatin1(signature.toBase64());
    reply["userHandle"] = userHandle;
    reply["userName"] = userName;
    reply["userDisplayName"] = matchedEntry->title().isEmpty() ? userName : matchedEntry->title();

    return reply;
}

QJsonObject WindowsPasskeyService::handleUnlockDatabase(const QJsonObject& req)
{
    QJsonObject reply;
    reply["type"] = "unlock_database";

    bool bringToFront = req.value("bringToFront").toBool(true);
    if (m_mainWindow && bringToFront) {
        auto hwnd = reinterpret_cast<HWND>(m_mainWindow->winId());
        SetForegroundWindow(hwnd);
    }

    auto dbs = openDatabases();
    if (!dbs.isEmpty()) {
        reply["unlocked"] = true;
        reply["busy"] = false;
        return reply;
    }

    if (m_mainWindow) {
        auto* tabWidget = m_mainWindow->findChild<DatabaseTabWidget*>();
        if (tabWidget) {
            tabWidget->performBrowserUnlock();
        }
    }

    dbs = openDatabases();
    reply["unlocked"] = !dbs.isEmpty();
    reply["busy"] = false;

    return reply;
}

void WindowsPasskeyService::initSettings()
{
    // Default settings: Default to Notification mode (no Windows Hello PIN prompt required!)
    m_settings["logLevel"] = "Info";
    m_settings["newPasskeyBackupEligible"] = true;
    m_settings["newPasskeyBackupState"] = true;
    m_settings["userVerificationMode"] = "Notification";
    m_settings["registrationVerification"] = "Notification";
    m_settings["signInVerification"] = "Notification";
    m_settings["excludeCredentialCheckMode"] = "TargetDatabase";
    m_settings["newEntryGroupMode"] = "PasskeysGroup";
    m_settings["entryTitleTemplate"] = "{RP_NAME} (Passkey)";
    m_settings["resolveTitlePlaceholders"] = true;
    m_settings["saveToExistingEntry"] = true;
    m_settings["addPasskeyTag"] = true;
    m_settings["showErrorNotifications"] = true;
    m_settings["useLegacyNotificationPrompts"] = false;
    m_settings["skipWindowsHelloAfterUnlock"] = false;
    m_settings["notificationVerificationTimeoutMilliseconds"] = 60000;

    // Load persisted settings from KeePassXC QSettings
    QSettings config;
    config.beginGroup(QStringLiteral("WindowsPasskey"));
    QString jsonStr = config.value(QStringLiteral("SettingsJson")).toString();
    config.endGroup();

    if (!jsonStr.isEmpty()) {
        QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8());
        if (doc.isObject()) {
            const auto saved = doc.object();
            for (auto it = saved.constBegin(); it != saved.constEnd(); ++it) {
                m_settings[it.key()] = it.value();
            }
        }
    }
}

void WindowsPasskeyService::saveSettingsToDisk()
{
    QJsonDocument doc(m_settings);
    QString jsonStr = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));

    QSettings config;
    config.beginGroup(QStringLiteral("WindowsPasskey"));
    config.setValue(QStringLiteral("SettingsJson"), jsonStr);
    config.endGroup();
}

QJsonObject WindowsPasskeyService::handleGetSettings(const QJsonObject&)
{
    QJsonObject reply;
    reply["type"] = "get_settings";
    reply["settings"] = m_settings;
    return reply;
}

QJsonObject WindowsPasskeyService::handleSaveSettings(const QJsonObject& req)
{
    QJsonObject reply;
    reply["type"] = "save_settings";

    if (req.contains("settings") && req["settings"].isObject()) {
        const auto newSettings = req["settings"].toObject();
        for (auto it = newSettings.constBegin(); it != newSettings.constEnd(); ++it) {
            m_settings[it.key()] = it.value();
        }
        saveSettingsToDisk();
    }

    return reply;
}

bool WindowsPasskeyService::generateKeyPair(int alg, QByteArray& outCoseKey, QString& outPrivateKeyPem)
{
    try {
        if (alg == -7) { // ES256 (secp256r1)
            Botan::ECDSA_PrivateKey privateKey(*randomGen()->getRng(), Botan::EC_Group("secp256r1"));
            const auto& publicPoint = privateKey.public_point();
            auto x = publicPoint.get_affine_x();
            auto y = publicPoint.get_affine_y();
            QByteArray xBytes = bigIntToQByteArray(x);
            QByteArray yBytes = bigIntToQByteArray(y);

            BrowserCbor cbor;
            outCoseKey = cbor.cborEncodePublicKey(-7, xBytes, yBytes);
            outPrivateKeyPem = QString::fromStdString(Botan::PKCS8::PEM_encode(privateKey));
            return !outCoseKey.isEmpty() && !outPrivateKeyPem.isEmpty();
        } else if (alg == -8) { // Ed25519
            Botan::Ed25519_PrivateKey privateKey(*randomGen()->getRng());
            auto pubKeyBits = privateKey.get_public_key();
            QByteArray pubBytes(reinterpret_cast<const char*>(pubKeyBits.data()), static_cast<qsizetype>(pubKeyBits.size()));

            BrowserCbor cbor;
            outCoseKey = cbor.cborEncodePublicKey(-8, pubBytes, QByteArray());
            outPrivateKeyPem = QString::fromStdString(Botan::PKCS8::PEM_encode(privateKey));
            return !outCoseKey.isEmpty() && !outPrivateKeyPem.isEmpty();
        }
    } catch (std::exception& e) {
        qWarning() << "WindowsPasskeyService::generateKeyPair failed:" << e.what();
    }
    return false;
}

QByteArray WindowsPasskeyService::signData(const QString& privateKeyPem, const QByteArray& dataToSign)
{
    try {
        QByteArray keyBytes = privateKeyPem.toUtf8();
        Botan::DataSource_Memory dataSource(reinterpret_cast<const uint8_t*>(keyBytes.constData()), keyBytes.size());
        auto key = Botan::PKCS8::load_key(dataSource);
        if (!key) {
            return {};
        }

        const auto algName = key->algo_name();
        const auto algId = key->algorithm_identifier();
        const auto privBits = key->private_key_bits();

        std::vector<uint8_t> rawSignature;
        if (algName == "ECDSA") {
            Botan::ECDSA_PrivateKey ecKey(algId, privBits);
#ifdef WITH_BOTAN3
            Botan::PK_Signer signer(ecKey, *randomGen()->getRng(), "EMSA1(SHA-256)", Botan::Signature_Format::DerSequence);
#else
            Botan::PK_Signer signer(ecKey, *randomGen()->getRng(), "EMSA1(SHA-256)", Botan::DER_SEQUENCE);
#endif
            signer.update(reinterpret_cast<const uint8_t*>(dataToSign.constData()), dataToSign.size());
            rawSignature = signer.signature(*randomGen()->getRng());
        } else if (algName == "Ed25519") {
            Botan::Ed25519_PrivateKey edKey(algId, privBits);
            Botan::PK_Signer signer(edKey, *randomGen()->getRng(), "Raw");
            signer.update(reinterpret_cast<const uint8_t*>(dataToSign.constData()), dataToSign.size());
            rawSignature = signer.signature(*randomGen()->getRng());
        }

        return QByteArray(reinterpret_cast<const char*>(rawSignature.data()), static_cast<qsizetype>(rawSignature.size()));
    } catch (std::exception& e) {
        qWarning() << "WindowsPasskeyService::signData exception:" << e.what();
        return {};
    }
}

QString WindowsPasskeyService::entryIconBase64(Entry* entry)
{
    if (!entry) {
        return {};
    }

    QPixmap pixmap;
    if (!entry->iconUuid().isNull() && entry->database()) {
        const auto& custom = entry->database()->metadata()->customIcon(entry->iconUuid());
        if (!custom.data.isEmpty()) {
            pixmap.loadFromData(custom.data);
        }
    }
    if (pixmap.isNull()) {
        pixmap = databaseIcons()->icon(entry->iconNumber());
    }
    if (pixmap.isNull()) {
        QIcon qicon = icons()->icon("passkey");
        pixmap = qicon.pixmap(32, 32);
    }
    if (pixmap.isNull()) {
        return {};
    }

    QByteArray bytes;
    QBuffer buffer(&bytes);
    buffer.open(QIODevice::WriteOnly);
    pixmap.save(&buffer, "PNG");
    return QString::fromLatin1(bytes.toBase64());
}

void WindowsPasskeyService::notifyCredentialsChanged()
{
    // Try to trigger KeePassPasskeyProvider.exe /synccredential
    QStringList candidates;

    // 1. AppData Local Microsoft WindowsApps
    QString localAppData = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
    candidates << QString("%1/Microsoft/WindowsApps/KeePassPasskeyProvider.exe").arg(localAppData);

    // 2. Dev build directory if present
    candidates << QStringLiteral("D:/Projects/KeePassPasskey/build/Debug/KeePassPasskeyProvider/KeePassPasskeyProvider.exe");

    for (const auto& path : candidates) {
        if (QFile::exists(path)) {
            QProcess::startDetached(path, QStringList() << QStringLiteral("/synccredential"));
            break;
        }
    }
}
