#pragma once

#include <Sailfish/Crypto/Plugins/extensionplugins.h>

#include <QObject>

namespace Sailfish {
namespace Crypto {
namespace Daemon {
namespace Plugins {

class Q_DECL_EXPORT GostCryptoPlugin : public QObject, public virtual Sailfish::Crypto::CryptoPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)
    Q_INTERFACES(Sailfish::Crypto::CryptoPlugin)

public:
    GostCryptoPlugin(QObject* parent = nullptr);
    ~GostCryptoPlugin();

public:
    QString displayName() const override {
        return QStringLiteral("Gost Crypto");
    }

    QString name() const override {
#ifdef SAILFISHCRYPTO_TESTPLUGIN
        return QLatin1String("org.sailfishos.plugin.encryption.gost.test");
#else
        return QLatin1String("org.sailfishos.plugin.encryption.gost");
#endif
    }

    int version() const override {
        return 1;
    }

    Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const override {
        return Sailfish::Crypto::CryptoPlugin::SoftwareEncryption;
    }

    bool canStoreKeys() const override {
        return true;
    }

    Sailfish::Crypto::Result generateRandomData(
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes,
        const QVariantMap &customParameters,
        QByteArray *randomData) override;

    Sailfish::Crypto::Result seedRandomDataGenerator(
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate,
        const QVariantMap &customParameters) override;

    Sailfish::Crypto::Result generateInitializationVector(
        Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        int keySize,
        const QVariantMap &customParameters,
        QByteArray *generatedIV) override;

    Sailfish::Crypto::Result generateKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *key) override;

    Sailfish::Crypto::Result generateAndStoreKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *keyMetadata) override;

    Sailfish::Crypto::Result importKey(
        const QByteArray &data,
        const QByteArray &passphrase,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *importedKey) override;

    Sailfish::Crypto::Result importAndStoreKey(
        const QByteArray &data,
        const Sailfish::Crypto::Key &keyTemplate,
        const QByteArray &passphrase,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *keyMetadata) override;

    Sailfish::Crypto::Result storedKey(
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::Key::Components keyComponents,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *key) override;

    Sailfish::Crypto::Result storedKeyIdentifiers(
        const QString &collectionName,
        const QVariantMap &customParameters,
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers) override;

    Sailfish::Crypto::Result calculateDigest(
        const QByteArray &data,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        QByteArray *digest) override;

    Sailfish::Crypto::Result sign(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        QByteArray *signature) override;

    Sailfish::Crypto::Result verify(
        const QByteArray &signature,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) override;

    Sailfish::Crypto::Result encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        QByteArray *encrypted,
        QByteArray *authenticationTag) override;

    Sailfish::Crypto::Result decrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QByteArray &authenticationTag,
        const QVariantMap &customParameters,
        QByteArray *decrypted,
        Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus);

    Sailfish::Crypto::Result initializeCipherSession(
        quint64 clientId,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        Sailfish::Crypto::CryptoManager::Operation operation,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
        Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        quint32 *cipherSessionToken) override;

    Sailfish::Crypto::Result updateCipherSessionAuthentication(
        quint64 clientId,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken) override;

    Sailfish::Crypto::Result updateCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken,
        QByteArray *generatedData) override;

    Sailfish::Crypto::Result finalizeCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken,
        QByteArray *generatedData,
        Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) override;
};

} // Namespace Plugins
} // Namespace Daemon
} // namespace Crypto
} // namespace Sailfish
