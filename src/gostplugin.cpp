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

        enum class GenerateKeyType {
            SymmetricKey = 0,
            AsymmetricKeyPair = 1
        };

        enum class GenerateKeyParams {
            WithPbkdfParams = 0,
            WithoutPbkdfParams = 1,
        };

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
            constexpr auto privateKeyLength = OPENSSL_HELPER_GOST_SIGNATURE_KEY_SIZE;

            QByteArray randomKey;

            const auto randomResult = GenerateRandomData(
                QStringLiteral("/dev/urandom"),
                privateKeyLength,
                &randomKey);

            if (randomResult.code() != Result::Succeeded) {
                return randomResult;
            }

            *key = keyTemplate;
            key->setSecretKey(randomKey);
            key->setSize(privateKeyLength);

            return Result(Result::Succeeded);
        }

        Result GenerateKeyWithPbkdf(
            const Key &keyTemplate,
            const KeyDerivationParameters &skdfParams,
            Key *key)
        {
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

            constexpr auto privateKeyLength = OPENSSL_HELPER_GOST_SIGNATURE_KEY_SIZE;
            QScopedArrayPointer<char> buf(new char[privateKeyLength]);

            const int rc = openssl_helper_pbkdf2_256_out(
                skdfParams.inputData().constData(),
                skdfParams.inputData().size(),

                skdfParams.salt().isEmpty()
                    ? Q_NULLPTR
                    : reinterpret_cast<const unsigned char*>(skdfParams.salt().constData()),
                skdfParams.salt().size(),

                skdfParams.iterations(),

                reinterpret_cast<unsigned char*>(buf.data()),
                privateKeyLength);

            if (rc < 0) {
                return Result(
                    Result::CryptoPluginKeyGenerationError,
                    QLatin1String("Gost crypto plugin failed to derive the private key data: ") +
                    QLatin1String(openssl_helper_errstr));
            }

            *key = keyTemplate;
            key->setSecretKey(QByteArray(buf.data(), privateKeyLength));
            key->setSize(privateKeyLength);

            return Result(Result::Succeeded);
        }

        Result GenerateKeyPrivate(
            const Key &keyTemplate,
            const KeyDerivationParameters& skdfParams,
            const GenerateKeyParams& generateKeyParams,
            Key *key)
        {
            switch (generateKeyParams) {
            case GenerateKeyParams::WithoutPbkdfParams: {
                return GenerateKeyWithoutPbkdf(keyTemplate, key);
            }
            case GenerateKeyParams::WithPbkdfParams: {
                return GenerateKeyWithPbkdf(keyTemplate, skdfParams, key);
            }
            } // switch

            return Result(Result::Succeeded);
        }

        Result GenerateKeyPublic(
            const Key& privateKey,
            const KeyPairGenerationParameters& kpgParams,
            const GenerateKeyType& generateKeyType,
            Key *publicKey)
        {
            Q_UNUSED(kpgParams);

            constexpr auto publicKeySize = OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE;
            constexpr auto privateKeySize = OPENSSL_HELPER_GOST_SIGNATURE_KEY_SIZE;

            qDebug() << "publicKeySize = " << publicKeySize;

            if (privateKey.size() != privateKeySize) {
                const auto msg =
                    QStringLiteral("Gost plugin size of private key must be %1, yours %2")
                    .arg(privateKeySize * 8 /*bits*/).arg(privateKey.size());
                return Result(
                    Result::CryptoPluginKeyGenerationError,
                    msg);
            }

            switch (generateKeyType) {
            case GenerateKeyType::SymmetricKey: {
                break;
            }
            case GenerateKeyType::AsymmetricKeyPair: {
                QScopedArrayPointer<char> buf(new char[publicKeySize]);

                const int rc = openssl_helper_compute_public_256_out(
                    privateKey.secretKey(),
                    privateKey.secretKey().size(),

                    reinterpret_cast<unsigned char*>(buf.data()),
                    publicKeySize);

                if (rc < 0) {
                    return Result(
                        Result::CryptoPluginKeyGenerationError,
                        QLatin1String("Gost crypto plugin failed to create public key: ") +
                        QLatin1String(openssl_helper_errstr));
                }

                *publicKey = privateKey;
                publicKey->setSecretKey(QByteArray(buf.data(), publicKeySize));
                publicKey->setSize(publicKeySize);
            }
            } // switch

            return Result(Result::Succeeded);
        }

        Result GenerateKey(
            const Key& keyTemplate,
            const KeyPairGenerationParameters& kpgParams,
            const KeyDerivationParameters& skdfParams,
            const GenerateKeyType& generateKeyType,
            const GenerateKeyParams& generateKeyParams,
            Key *key)
        {
            *key = keyTemplate;

            Key privateKey;
            const auto resultPrivate =
                GenerateKeyPrivate(keyTemplate, skdfParams, generateKeyParams, &privateKey);

            if (resultPrivate != Result(Result::Succeeded)) {
                return resultPrivate;
            }

            if (generateKeyType == GenerateKeyType::SymmetricKey) {
                key->setSecretKey(privateKey.secretKey());
                key->setSize(privateKey.size());
                return Result(Result::Succeeded);
            }

            Key publicKey;
            const auto resultPublic =
                GenerateKeyPublic(privateKey, kpgParams, generateKeyType, &publicKey);

            if (resultPublic != Result(Result::Succeeded)) {
                return resultPublic;
            }

            key->setPrivateKey(privateKey.secretKey());
            key->setPublicKey(publicKey.secretKey());
            key->setSize(privateKey.size());

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

        Result CalculateDigest(
            const QByteArray& data,
            QByteArray& digest)
        {
            constexpr auto digestSize = OPENSSL_HELPER_GOST_DIGEST_SIZE;

            QScopedPointer<char> digestBytes(new char[digestSize]);

            const int rc = openssl_helper_digest_256_out(
                data.data(),
                data.size(),
                digestBytes.data(),
                digestSize);

            if (rc < 0) {
                return Result(
                    Result::CryptoPluginDigestError,
                    QLatin1String("Gost error when call digest function: ") +
                    QLatin1String(openssl_helper_errstr));
            }

            digest = QByteArray(digestBytes.data(), digestSize);

            return Result(Result::Succeeded);
        }

        Result CalculateSignature(
            const QByteArray& privateKey,
            const QByteArray& data,
            QByteArray& signature)
        {
            constexpr auto signatureSize = OPENSSL_HELPER_GOST_SIGNATURE_SIZE;

            qDebug() << "signatureSize = " << signatureSize;

            QScopedPointer<char> signatureBytes(new char[signatureSize]);

            const int rc = openssl_helper_sign_256_out(
                privateKey.data(),
                privateKey.size(),

                data.data(),
                data.size(),

                signatureBytes.data(),
                signatureSize);

            if (rc < 0) {
                return Result(
                    Result::CryptoPluginSigningError,
                    QLatin1String("Gost error when sign data: ") +
                    QLatin1String(openssl_helper_errstr));
            }

            signature = QByteArray(signatureBytes.data(), signatureSize);

            return Result(Result::Succeeded);
        }

        Result VerifySignature(
            const QByteArray& ,
            const QByteArray& data,
            const QByteArray& signature)
        {
            const QByteArray wrongKey('a', OPENSSL_HELPER_GOST_SIGNATURE_PUBLIC_KEY_SIZE);
            const int rc = openssl_helper_verify_256(
                wrongKey.data(),
                wrongKey.size(),

                data.data(),
                data.size(),

                signature.data(),
                signature.size());

            if (rc < 0) {
                return Result(
                    Result::CryptoPluginVerificationError,
                    QLatin1String("Gost error when verify signature: ") +
                    QLatin1String(openssl_helper_errstr));
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

    Result GostCryptoPlugin::generateRandomData(
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

    Result GostCryptoPlugin::seedRandomDataGenerator(
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

    Result GostCryptoPlugin::generateInitializationVector(
        CryptoManager::Algorithm algorithm,
        CryptoManager::BlockMode blockMode,
        int keySize,
        const QVariantMap &customParameters,
        QByteArray *generatedIV)
    {
        Q_UNUSED(customParameters);

        if (algorithm != CryptoManager::AlgorithmGost) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost: iv: cannot use algorithms other than Gost"));
        }

        if (blockMode != CryptoManager::BlockModeOfb) {
            return Result(
                Result::OperationNotSupportedError,
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
        Q_UNUSED(customParameters);

        if (keyTemplate.size() < OPENSSL_HELPER_KUZNYECHIK_KEY_SIZE or
            (keyTemplate.size() % 8 /*padded to 1 byte*/) != 0)
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

        const GenerateKeyType keyType = kpgParams.isValid()
            ? GenerateKeyType::AsymmetricKeyPair
            : GenerateKeyType::SymmetricKey;

        const GenerateKeyParams keyParams = skdfParams.isValid()
            ? GenerateKeyParams::WithPbkdfParams
            : GenerateKeyParams::WithoutPbkdfParams;

        return GenerateKey(keyTemplate, kpgParams, skdfParams, keyType, keyParams, key);
    }

    Result GostCryptoPlugin::generateAndStoreKey(
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        Key *keyMetadata)
    {
        Q_UNUSED(keyTemplate);
        Q_UNUSED(kpgParams);
        Q_UNUSED(skdfParams);
        Q_UNUSED(customParameters);
        Q_UNUSED(keyMetadata);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("Gost crypto plugin doesn't support generateAndStoreKey"));
    }

    Result GostCryptoPlugin::importKey(
        const QByteArray &data,
        const QByteArray &passphrase,
        const QVariantMap &customParameters,
        Key *importedKey)
    {
        Q_UNUSED(data);
        Q_UNUSED(passphrase);
        Q_UNUSED(customParameters);
        Q_UNUSED(importedKey);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support importKey"));
    }

    Result GostCryptoPlugin::importAndStoreKey(
        const QByteArray &data,
        const Key &keyTemplate,
        const QByteArray &passphrase,
        const QVariantMap &customParameters,
        Key *keyMetadata)
    {
        Q_UNUSED(data);
        Q_UNUSED(keyTemplate);
        Q_UNUSED(passphrase);
        Q_UNUSED(customParameters);
        Q_UNUSED(keyMetadata);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support importAndStoreKey"));
    }

    Result GostCryptoPlugin::storedKey(
        const Key::Identifier &identifier,
        Key::Components keyComponents,
        const QVariantMap &customParameters,
        Key *key)
    {
        Q_UNUSED(identifier);
        Q_UNUSED(keyComponents);
        Q_UNUSED(customParameters);
        Q_UNUSED(key);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("The OpenSSL crypto plugin doesn't support storedKey"));
    }

    Result GostCryptoPlugin::storedKeyIdentifiers(
        const QString &collectionName,
        const QVariantMap &customParameters,
        QVector<Key::Identifier> *identifiers)
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
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost cannot digest padding other than None"));
        }

        if (digestFunction != CryptoManager::DigestGost_2012_256) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost cannot has digest other than DigestGost_2012_256"));
        }

        return CalculateDigest(data, *digest);
    }

    Result GostCryptoPlugin::sign(
        const QByteArray &data,
        const Key &key,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        QByteArray *signature)
    {
        Q_UNUSED(customParameters);

        if (data.isEmpty()) {
            return Result(
                Result::EmptyDataError,
                QLatin1String("Gost cannot sign data if there is no data"));
        }

        if (key.privateKey().isEmpty()) {
            return Result(
                Result::EmptyDataError,
                QLatin1String("Gost cannot sign data without private key"));
        }

        if (padding != CryptoManager::SignaturePaddingNone) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost cannot sign padding other than None"));
        }

        if (digestFunction != CryptoManager::DigestGost_2012_256) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost cannot has digest other than DigestGost_2012_256"));
        }

        QByteArray digest;
        const auto digestResult = CalculateDigest(data, digest);

        if (digestResult != Result(Result::Succeeded)) {
            return digestResult;
        }

        if (digest.isEmpty()) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost error! Calculated digest is empty"));
        }

        qDebug() << "digest.size() = " << digest.size();
        qDebug() << "digest = " << digest;

        return CalculateSignature(key.privateKey(), digest, *signature);
    }

    Result GostCryptoPlugin::verify(
        const QByteArray &signature,
        const QByteArray &data,
        const Key &key,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        CryptoManager::VerificationStatus *verificationStatus)
    {
        Q_UNUSED(customParameters);

        if (data.isEmpty()) {
            return Result(
                Result::EmptyDataError,
                QLatin1String("Gost cannot verify data if there is no data"));
        }

        if (key.publicKey().isEmpty()) {
            return Result(
                Result::EmptyDataError,
                QLatin1String("Gost cannot verify data without public key"));
        }

        if (padding != CryptoManager::SignaturePaddingNone) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost cannot verify padding other than None"));
        }

        if (digestFunction != CryptoManager::DigestGost_2012_256) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost cannot has digest other than DigestGost_2012_256"));
        }

        QByteArray digest;
        const auto digestResult =
            CalculateDigest(data, digest);

        if (digestResult != Result(Result::Succeeded)) {
            return digestResult;
        }

        if (digest.isEmpty()) {
            return Result(
                Result::OperationNotSupportedError,
                QLatin1String("Gost error! Calculated digest is empty"));
        }

        const Result result =
            VerifySignature(key.publicKey(), digest, signature);

        *verificationStatus = result == Result(Result::Succeeded)
            ? CryptoManager::VerificationSucceeded
            : CryptoManager::VerificationFailed;

        return result;
    }

    Result GostCryptoPlugin::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        QByteArray *encrypted,
        QByteArray *authenticationTag)
    {
        Q_UNUSED(customParameters);

        if (encrypted == nullptr) {
            return Result(
                Result::CryptoPluginEncryptionError,
                QLatin1String("Gost the 'encrypted' argument SHOULD NOT be nullptr."));
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

    Result GostCryptoPlugin::initializeCipherSession(
        quint64 clientId,
        const QByteArray &iv,
        const Key &key, // or keyreference, i.e. Key(keyName)
        CryptoManager::Operation operation,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding encryptionPadding,
        CryptoManager::SignaturePadding signaturePadding,
        CryptoManager::DigestFunction digestFunction,
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

    Result GostCryptoPlugin::updateCipherSessionAuthentication(
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

    Result GostCryptoPlugin::updateCipherSession(
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

    Result GostCryptoPlugin::finalizeCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken,
        QByteArray *generatedData,
        CryptoManager::VerificationStatus *verificationStatus)
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
