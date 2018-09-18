#include "gostplugin.h"

#include <openssl/rand.h>

#include <openssl-helper/openssl-helper.h>

#include "Crypto/generaterandomdatarequest.h"

#include <QtCore/QDebug>

#include <fstream>

namespace Sailfish {
namespace Crypto {
namespace Daemon {
namespace Plugins {

    namespace {

        Result GenerateRandomData(
            const QString &csprngEngineName,
            const quint64 nbytes,
            QByteArray *randomData)
        {
            constexpr int MAX_BYTES = 4096;
            const bool useDevURandom = csprngEngineName == QStringLiteral("/dev/urandom");

            if (not nbytes or nbytes > MAX_BYTES) {
                return Result(
                    Result::CryptoPluginRandomDataError,
                    QLatin1String("This crypto plugin can only generate up to 4096 bytes of random data at a time"));
            }

            QScopedArrayPointer<char> buf(new char[nbytes]);

            if (useDevURandom) {
                std::ifstream rand("/dev/urandom");
                rand.read(buf.data(), nbytes);
                rand.close();
            } else if (RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), nbytes) != 1) {
                return Result(
                    Result::CryptoPluginRandomDataError,
                    QLatin1String("This crypto plugin failed to generate the random data"));
            }

            *randomData = QByteArray(reinterpret_cast<const char *>(buf.data()), nbytes);

            return Result(Result::Succeeded);
        }

        Result GenerateKeyWithoutPbkdf(
            const Key &keyTemplate,
            Key *key)
        {
            QByteArray randomKey;

            const auto randomResult = GenerateRandomData(
                QStringLiteral("/dev/urandom"),
                keyTemplate.size() / 8,
                &randomKey);

            if (randomResult.code() != Result::Succeeded) {
                return randomResult;
            }

            *key = keyTemplate;
            key->setSecretKey(randomKey);
            key->setSize(keyTemplate.size());

            return Result(Result::Succeeded);
        }

        Result GenerateKeyWithPbkdf(
            const Key &keyTemplate,
            const KeyDerivationParameters &skdfParams,
            Key *key)
        {
            const int nbytes = skdfParams.outputKeySize() / 8;
            QScopedArrayPointer<char> buf(new char[nbytes]);

            const int rc = openssl_helper_pbkdf2_256_out(
                skdfParams.inputData().constData(),
                skdfParams.inputData().size(),

                skdfParams.salt().isEmpty()
                ? Q_NULLPTR
                : reinterpret_cast<const unsigned char*>(skdfParams.salt().constData()),
                skdfParams.salt().size(),

                skdfParams.iterations(),

                reinterpret_cast<unsigned char*>(buf.data()),
                nbytes);

            if (rc < 0) {
                return Result(
                    Result::CryptoPluginKeyGenerationError,
                    QLatin1String("Gost crypto plugin failed to derive the key data: ") +
                    QLatin1String(openssl_helper_errstr));
            }

            *key = keyTemplate;
            key->setSecretKey(QByteArray(buf.data(), nbytes));
            key->setSize(skdfParams.outputKeySize());

            return Result(Result::Succeeded);
        }

        Result EncryptWithKuznyechikOfb(
            const QByteArray& key,
            const QByteArray& iv,
            const QByteArray& data,
            QByteArray* encrypted)
        {
            QScopedArrayPointer<char> buf(new char[data.size()]);

            const int rc = openssl_helper_ofb_kuznyechik_out(
                OPENSSL_HELPER_ENCRYPTION,

                key.constData(),
                key.size(),

                iv.constData(),
                iv.size(),

                data.constData(),
                data.size(),

                reinterpret_cast<unsigned char*>(buf.data()),
                data.size());

            if (rc < 0) {
                return Result(
                    Result::CryptoPluginEncryptionError,
                    QLatin1String("Gost crypto plugin failed to encrypt: ") +
                    QLatin1String(openssl_helper_errstr));
            }

            *encrypted = QByteArray(buf.data(), data.size());

            if (encrypted->isEmpty()) {
                return Result(
                    Result::CryptoPluginEncryptionError,
                    QLatin1String("Gost crypto plugin failed to encrypt the data"));
            }

            return Result(Result::Succeeded);
        }

        Result DecryptWithKuznyechikOfb(
            const QByteArray& key,
            const QByteArray& iv,
            const QByteArray& data,
            QByteArray* encrypted)
        {
            QScopedArrayPointer<char> buf(new char[data.size()]);

            const int rc = openssl_helper_ofb_kuznyechik_out(
                OPENSSL_HELPER_DECRYPTION,

                key.constData(),
                key.size(),

                iv.constData(),
                iv.size(),

                data.constData(),
                data.size(),

                reinterpret_cast<unsigned char*>(buf.data()),
                data.size());

            if (rc < 0) {
                return Result(
                    Result::CryptoPluginEncryptionError,
                    QLatin1String("Gost crypto plugin failed to encrypt: ") +
                    QLatin1String(openssl_helper_errstr));
            }

            *encrypted = QByteArray(buf.data(), data.size());

            if (encrypted->isEmpty()) {
                return Result(
                    Result::CryptoPluginEncryptionError,
                    QLatin1String("Gost crypto plugin failed to encrypt the data"));
            }

            return Result(Result::Succeeded);
        }

    } // anonymous namespace

    GostCryptoPlugin::GostCryptoPlugin(QObject* parent)
        : QObject(parent)
    {
        openssl_helper_initialize();
    }

    GostCryptoPlugin::~GostCryptoPlugin()
    {

    }

    Sailfish::Crypto::Result GostCryptoPlugin::generateRandomData(
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes,
        const QVariantMap &customParameters,
        QByteArray *randomData)
    {
        Q_UNUSED(callerIdent);
        Q_UNUSED(customParameters);

        return GenerateRandomData(csprngEngineName, numberBytes, randomData);
    }

    Sailfish::Crypto::Result GostCryptoPlugin::seedRandomDataGenerator(
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate,
        const QVariantMap &customParameters)
    {
        Q_UNUSED(callerIdent);
        Q_UNUSED(customParameters);

        if (csprngEngineName != GenerateRandomDataRequest::DefaultCsprngEngineName) {
            return Result(Result::CryptoPluginRandomDataError,
                          QLatin1String("The OpenSSL crypto plugin doesn't currently support other RNG engines"));
        }

        RAND_add(seedData.constData(), seedData.size(), entropyEstimate);
        return Result(Result::Succeeded);
    }

    Sailfish::Crypto::Result GostCryptoPlugin::generateInitializationVector(
        Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        int keySize,
        const QVariantMap &customParameters,
        QByteArray *generatedIV)
    {
        Q_UNUSED(customParameters);

        if (algorithm != Sailfish::Crypto::CryptoManager::AlgorithmGost) {
            return Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::OperationNotSupportedError,
                QLatin1String("Gost: iv: cannot use algorithms other than Gost"));
        }

        if (blockMode != Sailfish::Crypto::CryptoManager::BlockModeOfb) {
            return Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::OperationNotSupportedError,
                QLatin1String("Gost: iv: cannot encrypt with block mode other than OFB"));
        }

        return GenerateRandomData(QStringLiteral("/dev/urandom"), keySize, generatedIV);
    }

    Result GostCryptoPlugin::generateKey(
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        Key *key)
    {
        Q_UNUSED(kpgParams);
        Q_UNUSED(customParameters);

        if (keyTemplate.size() < OPENSSL_HELPER_KUZNYECHIK_KEY_SIZE or
            (keyTemplate.size() % 8) != 0)
        {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost unsupported key size specified"));
        }

        if (keyTemplate.algorithm() != CryptoManager::AlgorithmGost) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost plugin cannot use algorithms other than Gost"));
        }

        if (not skdfParams.isValid()) {
            return GenerateKeyWithoutPbkdf(keyTemplate, key);
        }

        // use key derivation to derive a key from input data.
        if (skdfParams.keyDerivationFunction() != CryptoManager::KdfPkcs5Pbkdf2) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost unsupported key derivation function specified"));
        }

        if (skdfParams.keyDerivationMac() != CryptoManager::MacHmac) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost unsupported key derivation message authentication code specified"));
        }

        if (skdfParams.keyDerivationDigestFunction() != CryptoManager::DigestGost_2012_256) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost unsupported key derivation digest function specified"));
        }

        if (skdfParams.iterations() < 0 || skdfParams.iterations() > 32768) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost unsupported iterations specified"));
        }

        return GenerateKeyWithPbkdf(keyTemplate, skdfParams, key);
    }

    Sailfish::Crypto::Result GostCryptoPlugin::generateAndStoreKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *keyMetadata)
    {
        Q_UNUSED(keyTemplate);
        Q_UNUSED(kpgParams);
        Q_UNUSED(skdfParams);
        Q_UNUSED(customParameters);
        Q_UNUSED(keyMetadata);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("Gost crypto plugin doesn't support generateAndStoreKey"));
    }

    Sailfish::Crypto::Result GostCryptoPlugin::importKey(
        const QByteArray &data,
        const QByteArray &passphrase,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *importedKey)
    {
        Q_UNUSED(data);
        Q_UNUSED(passphrase);
        Q_UNUSED(customParameters);
        Q_UNUSED(importedKey);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support importKey"));
    }

    Sailfish::Crypto::Result GostCryptoPlugin::importAndStoreKey(
        const QByteArray &data,
        const Sailfish::Crypto::Key &keyTemplate,
        const QByteArray &passphrase,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *keyMetadata)
    {
        Q_UNUSED(data);
        Q_UNUSED(keyTemplate);
        Q_UNUSED(passphrase);
        Q_UNUSED(customParameters);
        Q_UNUSED(keyMetadata);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support importAndStoreKey"));
    }

    Sailfish::Crypto::Result GostCryptoPlugin::storedKey(
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::Key::Components keyComponents,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *key)
    {
        Q_UNUSED(identifier);
        Q_UNUSED(keyComponents);
        Q_UNUSED(customParameters);
        Q_UNUSED(key);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support storedKey"));
    }

    Sailfish::Crypto::Result GostCryptoPlugin::storedKeyIdentifiers(
        const QString &collectionName,
        const QVariantMap &customParameters,
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
    {
        Q_UNUSED(collectionName);
        Q_UNUSED(customParameters);
        Q_UNUSED(identifiers);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support storedKeyIdentifiers"));
    }

    Result GostCryptoPlugin::calculateDigest(
        const QByteArray &data,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        QByteArray *digest)
    {
        Q_UNUSED(customParameters);

        if (digest == nullptr) {
            return Result(
                Result::CryptoPluginDigestError,
                QLatin1String("Gost cannot receive output argument 'digest' was nullptr."));
        }

        if (data.isEmpty()) {
            return Result(
                Result::EmptyDataError,
                QLatin1String("Gost cannot digest data if there is no data."));
        }

        if (padding != CryptoManager::SignaturePaddingNone) {
            return Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::OperationNotSupportedError,
                QLatin1String("Gost cannot digest padding other than None"));
        }

        if (digestFunction != CryptoManager::DigestGost_2012_256) {
            return Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::OperationNotSupportedError,
                QLatin1String("Gost cannot has digest other than DigestGost_2012_256"));
        }

        QScopedPointer<char> digestBytes(new char[OPENSSL_HELPER_GOST_DIGEST_SIZE]);

        const int rc = openssl_helper_digest_256_out(
            data.data(),
            data.size(),
            digestBytes.data(),
            OPENSSL_HELPER_GOST_DIGEST_SIZE);

        if (rc < 0) {
            return Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::CryptoPluginDigestError,
                QLatin1String("Gost error when call digest function: ") +
                QLatin1String(openssl_helper_errstr));
        }

        *digest = QByteArray(digestBytes.data(), OPENSSL_HELPER_GOST_DIGEST_SIZE);

        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    }

    Sailfish::Crypto::Result GostCryptoPlugin::sign(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        QByteArray *signature)
    {
        Q_UNUSED(data);
        Q_UNUSED(key);
        Q_UNUSED(padding);
        Q_UNUSED(digestFunction);
        Q_UNUSED(customParameters);
        Q_UNUSED(signature);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support sign"));
    }

    Sailfish::Crypto::Result GostCryptoPlugin::verify(
        const QByteArray &signature,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus)
    {
        Q_UNUSED(signature);
        Q_UNUSED(data);
        Q_UNUSED(key);
        Q_UNUSED(padding);
        Q_UNUSED(digestFunction);
        Q_UNUSED(customParameters);
        Q_UNUSED(verificationStatus);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support verify"));
    }

    Sailfish::Crypto::Result GostCryptoPlugin::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        QByteArray *encrypted,
        QByteArray *authenticationTag)
    {
        Q_UNUSED(customParameters);

        if (encrypted == nullptr) {
            return Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::CryptoPluginEncryptionError,
                QLatin1String("Gost the 'encrypted' argument SHOULD NOT be nullptr."));
        }

        if (key.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmGost) {
            return Sailfish::Crypto::Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost crypto plugin supports only Gost encrypt algorithm"));
        }

        if (key.secretKey().isEmpty()) {
            return Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::EmptySecretKeyError,
                QLatin1String("Gost cannot encrypt with empty secret key"));
        }

        if (iv.isEmpty()) {
            return Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::EmptySecretKeyError,
                QLatin1String("Gost cannot encrypt with empty iv"));
        }

        if (blockMode != Sailfish::Crypto::CryptoManager::BlockModeOfb) {
            return Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::OperationNotSupportedError,
                QLatin1String("Gost cannot encrypt with block mode other than OFB"));
        }

        if (padding != Sailfish::Crypto::CryptoManager::EncryptionPaddingNone) {
            return Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::OperationNotSupportedError,
                QLatin1String("Gost cannot encrypt with padding other than None"));
        }

        if (not authenticationData.isEmpty() and authenticationTag == nullptr) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost authenticated tag is nullptr when auth data is not"));
        }

        if (not authenticationData.isEmpty()) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost authenticated decryption is not supported"));
        }

        return EncryptWithKuznyechikOfb(
            key.secretKey(),
            iv,
            data,
            encrypted);
    }

    Result GostCryptoPlugin::decrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QByteArray &authenticationTag,
        const QVariantMap &customParameters,
        QByteArray *decrypted,
        CryptoManager::VerificationStatus *verificationStatus)
    {
        Q_UNUSED(customParameters);

        if (decrypted == nullptr) {
            return Result(
                Result::CryptoPluginEncryptionError,
                QLatin1String("Gost the 'decrypted' argument SHOULD NOT be nullptr."));
        }

        if (key.algorithm() != CryptoManager::AlgorithmGost) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost crypto plugin supports only Gost encrypt algorithm"));
        }

        if (key.secretKey().isEmpty()) {
            return Result(
                Result::EmptySecretKeyError,
                QLatin1String("Gost cannot encrypt with empty secret key"));
        }

        if (iv.isEmpty()) {
            return Result(
                Result::EmptySecretKeyError,
                QLatin1String("Gost cannot encrypt with empty iv"));
        }

        if (blockMode != CryptoManager::BlockModeOfb) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost cannot encrypt with block mode other than OFB"));
        }

        if (padding != CryptoManager::EncryptionPaddingNone) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost cannot encrypt with padding other than None"));
        }

        if (not authenticationData.isEmpty() and authenticationTag.isEmpty()) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost authenticated tag is empty when auth data is not"));
        }

        if (not authenticationData.isEmpty() or not authenticationTag.isEmpty()) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost authenticated decryption is not supported"));
        }

        if (not authenticationData.isEmpty() and verificationStatus == nullptr) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost authenticated decryption verificationStatus is nullptr"));
        }

        return DecryptWithKuznyechikOfb(
            key.secretKey(),
            iv,
            data,
            decrypted);
    }

    Sailfish::Crypto::Result GostCryptoPlugin::initializeCipherSession(
        quint64 clientId,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        Sailfish::Crypto::CryptoManager::Operation operation,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
        Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        quint32 *cipherSessionToken)
    {
        Q_UNUSED(clientId);
        Q_UNUSED(iv);
        Q_UNUSED(key);
        Q_UNUSED(operation);
        Q_UNUSED(blockMode);
        Q_UNUSED(encryptionPadding);
        Q_UNUSED(signaturePadding);
        Q_UNUSED(digestFunction);
        Q_UNUSED(customParameters);
        Q_UNUSED(cipherSessionToken);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support initializeCipherSession"));
    }

    Sailfish::Crypto::Result GostCryptoPlugin::updateCipherSessionAuthentication(
        quint64 clientId,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken)
    {
        Q_UNUSED(clientId);
        Q_UNUSED(authenticationData);
        Q_UNUSED(customParameters);
        Q_UNUSED(cipherSessionToken);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support updateCipherSessionAuthentication"));
    }

    Sailfish::Crypto::Result GostCryptoPlugin::updateCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken,
        QByteArray *generatedData)
    {
        Q_UNUSED(clientId);
        Q_UNUSED(data);
        Q_UNUSED(customParameters);
        Q_UNUSED(cipherSessionToken);
        Q_UNUSED(generatedData);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support updateCipherSession"));
    }

    Sailfish::Crypto::Result GostCryptoPlugin::finalizeCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken,
        QByteArray *generatedData,
        Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus)
    {
        Q_UNUSED(clientId);
        Q_UNUSED(data);
        Q_UNUSED(customParameters);
        Q_UNUSED(cipherSessionToken);
        Q_UNUSED(generatedData);
        Q_UNUSED(verificationStatus);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support finalizeCipherSession"));
    }

} // namespace Plugins
} // namespace Daemon
} // namespace Crypto
} // namespace Sailfish
