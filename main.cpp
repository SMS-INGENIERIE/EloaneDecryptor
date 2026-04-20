/**
 * EloaneDecryptor — Application GUI pour ouvrir les fichiers .eloane
 *
 * Double-cliquer sur un .eloane → saisir le mot de passe → voir le JSON
 *
 * Compilation :
 *   mkdir build && cd build
 *   cmake .. && cmake --build .
 */
#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QStyle>
#include <QScreen>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QIcon>
#ifdef Q_OS_WIN
#include <windows.h>
#endif
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

// ═══════════════════════════════════════════════════════════════
// Crypto (copie autonome de CryptoUtils pour le déchiffreur)
// ═══════════════════════════════════════════════════════════════

namespace EloaneDecrypt
{

constexpr int SALT_SIZE            = 16;
constexpr int AES_KEY_SIZE         = 32;
constexpr int HMAC_KEY_SIZE        = 32;
constexpr int IV_SIZE              = 16;
constexpr int HMAC_SIZE            = 32;
constexpr int MAGIC_SIZE           = 4;
constexpr int PBKDF2_ITER          = 600000;
constexpr int MASTER_BLOB_SIZE     = 80;  // 64 octets (aesKey+hmacKey) + padding AES = 80
constexpr int MASTER_TRAILER_SIZE  = IV_SIZE + MASTER_BLOB_SIZE; // 16 + 80 = 96
constexpr char MAGIC[4]            = {'E','L','O',0x01};
constexpr char MAGIC_V2[4]         = {'E','L','O',0x02};

// Clé maître universelle pour les fichiers v2 (.e-zo)
// Doit être IDENTIQUE à CryptoUtils::MASTER_KEY côté E-ZO
const unsigned char MASTER_KEY[AES_KEY_SIZE] = {
    0x66, 0xEE, 0x3B, 0xB9, 0x23, 0x20, 0x4F, 0xA6,
    0x04, 0x14, 0xAC, 0x11, 0x3B, 0x3A, 0x51, 0x91,
    0x88, 0x47, 0x79, 0x88, 0xB4, 0x10, 0x47, 0x9E,
    0x1B, 0x76, 0x7B, 0xD3, 0xE8, 0xC3, 0x7C, 0x4B
};

bool deriveKeys(const QByteArray &pw, const unsigned char *salt,
                unsigned char *aesKey, unsigned char *hmacKey)
{
    unsigned char derived[64];
    if (PKCS5_PBKDF2_HMAC(pw.constData(), pw.size(), salt, SALT_SIZE,
                          PBKDF2_ITER, EVP_sha256(), 64, derived) != 1)
        return false;
    memcpy(aesKey, derived, 32);
    memcpy(hmacKey, derived + 32, 32);
    OPENSSL_cleanse(derived, 64);
    return true;
}

QByteArray computeHmac(const unsigned char *key, const QByteArray &data)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key, HMAC_KEY_SIZE,
         reinterpret_cast<const unsigned char *>(data.constData()), data.size(), out, &len);
    return (len == HMAC_SIZE) ? QByteArray(reinterpret_cast<char *>(out), len) : QByteArray();
}

bool aesDecryptBuf(const QByteArray& ciphertext, const unsigned char* key,
                   const unsigned char* iv, QByteArray& plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    plaintext.resize(ciphertext.size() + 16);
    int len = 0, total = 0;
    bool ok = true;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) ok = false;
    if (ok && EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &len,
                                reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                                ciphertext.size()) != 1) ok = false;
    if (ok) total = len;
    if (ok && EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + len, &len) != 1) ok = false;
    if (ok) total += len;

    EVP_CIPHER_CTX_free(ctx);
    if (ok) plaintext.resize(total);
    return ok;
}

QString decrypt(const QString& filePath, const QString& password, bool& ok)
{
    ok = false;
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return "Impossible d'ouvrir le fichier.";

    QByteArray data = f.readAll();
    f.close();

    // 1. Détecter version
    if (data.size() < MAGIC_SIZE)
        return "Fichier trop petit.";

    bool isV1 = (memcmp(data.constData(), MAGIC,    MAGIC_SIZE) == 0);
    bool isV2 = (memcmp(data.constData(), MAGIC_V2, MAGIC_SIZE) == 0);
    if (!isV1 && !isV2)
        return "Ce n'est pas un fichier .eloane ou .e-zo valide.";

    // 2. Vérifier taille minimale
    int minSize = MAGIC_SIZE + SALT_SIZE + HMAC_SIZE + IV_SIZE + 16;
    if (isV2) minSize += MASTER_TRAILER_SIZE;
    if (data.size() < minSize)
        return "Fichier trop petit ou invalide.";

    // 3. Extraire les composants
    int off = MAGIC_SIZE;
    const unsigned char* salt = reinterpret_cast<const unsigned char*>(data.constData() + off);
    off += SALT_SIZE;
    QByteArray storedHmac = data.mid(off, HMAC_SIZE);
    off += HMAC_SIZE;

    // Payload = IV + ciphertext (exclut le trailer clé maître pour v2)
    QByteArray payload;
    if (isV2) {
        int payloadSize = data.size() - off - MASTER_TRAILER_SIZE;
        payload = data.mid(off, payloadSize);
    } else {
        payload = data.mid(off);
    }

    // 4. Dériver les clés depuis le mot de passe
    unsigned char aesKey[AES_KEY_SIZE], hmacKey[HMAC_KEY_SIZE];
    QByteArray pw = password.toUtf8();
    if (!deriveKeys(pw, salt, aesKey, hmacKey)) {
        OPENSSL_cleanse(aesKey, 32); OPENSSL_cleanse(hmacKey, 32);
        return "Erreur de dérivation de clé.";
    }

    // 5. Vérifier HMAC
    QByteArray computed = computeHmac(hmacKey, payload);
    if (computed.isEmpty() || CRYPTO_memcmp(storedHmac.constData(), computed.constData(), HMAC_SIZE) != 0) {
        OPENSSL_cleanse(aesKey, 32); OPENSSL_cleanse(hmacKey, 32);
        return "Mot de passe incorrect ou fichier modifié.";
    }

    // 6. Déchiffrer
    const unsigned char* iv = reinterpret_cast<const unsigned char*>(payload.constData());
    QByteArray ciphertext = payload.mid(IV_SIZE);

    QByteArray plaintext;
    bool decOk = aesDecryptBuf(ciphertext, aesKey, iv, plaintext);

    OPENSSL_cleanse(aesKey, 32);
    OPENSSL_cleanse(hmacKey, 32);

    if (!decOk)
        return "Erreur de déchiffrement.";

    ok = true;
    return QString::fromUtf8(plaintext);
}

} // namespace EloaneDecrypt

// ═══════════════════════════════════════════════════════════════
// Interface graphique
// ═══════════════════════════════════════════════════════════════

class DecryptorWindow : public QWidget
{
public:
    DecryptorWindow(const QString &initialFile = {}, QWidget *parent = nullptr)
        : QWidget(parent), m_filePath(initialFile)
    {
        setWindowTitle("Eloane / E-ZO Decryptor");
        setMinimumSize(700, 500);
        setAcceptDrops(true);

        auto *mainLayout = new QVBoxLayout(this);
        mainLayout->setSpacing(12);
        mainLayout->setContentsMargins(20, 20, 20, 20);

        // ── Titre ──
        auto* title = new QLabel("Déchiffreur de fichiers Eloane / E-ZO");
        title->setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;");
        title->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(title);

        // ── Fichier ──
        auto *fileLayout = new QHBoxLayout();
        auto *fileLabel = new QLabel("Fichier :");
        m_fileEdit = new QLineEdit();
        m_fileEdit->setReadOnly(true);
        m_fileEdit->setPlaceholderText("Glissez un fichier .eloane ou .e-zo ici ou cliquez Parcourir...");
        if (!m_filePath.isEmpty())
            m_fileEdit->setText(m_filePath);

        auto *browseBtn = new QPushButton("Parcourir...");
        connect(browseBtn, &QPushButton::clicked, this, &DecryptorWindow::browse);

        fileLayout->addWidget(fileLabel);
        fileLayout->addWidget(m_fileEdit, 1);
        fileLayout->addWidget(browseBtn);
        mainLayout->addLayout(fileLayout);

        // ── Mot de passe ──
        auto *pwLayout = new QHBoxLayout();
        auto *pwLabel = new QLabel("Mot de passe :");
        m_passwordEdit = new QLineEdit();
        m_passwordEdit->setEchoMode(QLineEdit::Password);
        m_passwordEdit->setPlaceholderText("Entrez le mot de passe de déchiffrement");
        connect(m_passwordEdit, &QLineEdit::returnPressed, this, &DecryptorWindow::decrypt);

        m_decryptBtn = new QPushButton("Déchiffrer");
        m_decryptBtn->setStyleSheet("QPushButton { background-color: #3498db; color: white; "
                                    "padding: 6px 20px; border-radius: 4px; font-weight: bold; }"
                                    "QPushButton:hover { background-color: #2980b9; }");
        connect(m_decryptBtn, &QPushButton::clicked, this, &DecryptorWindow::decrypt);

        pwLayout->addWidget(pwLabel);
        pwLayout->addWidget(m_passwordEdit, 1);
        pwLayout->addWidget(m_decryptBtn);
        mainLayout->addLayout(pwLayout);

        // ── Status ──
        m_statusLabel = new QLabel();
        m_statusLabel->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(m_statusLabel);

        // ── Contenu déchiffré ──
        m_contentEdit = new QTextEdit();
        m_contentEdit->setReadOnly(true);
        m_contentEdit->setFont(QFont("Consolas", 10));
        m_contentEdit->setPlaceholderText("Le contenu déchiffré apparaîtra ici...");
        mainLayout->addWidget(m_contentEdit, 1);

        // ── Bouton exporter ──
        auto *bottomLayout = new QHBoxLayout();
        m_exportBtn = new QPushButton("Exporter en JSON...");
        m_exportBtn->setEnabled(false);
        connect(m_exportBtn, &QPushButton::clicked, this, &DecryptorWindow::exportJson);
        bottomLayout->addStretch();
        bottomLayout->addWidget(m_exportBtn);
        mainLayout->addLayout(bottomLayout);

        // Focus sur le mot de passe si un fichier est déjà chargé
        if (!m_filePath.isEmpty())
        {
            m_passwordEdit->setFocus();
        }
    }

protected:
    void dragEnterEvent(QDragEnterEvent *e) override
    {
        if (e->mimeData()->hasUrls())
            e->acceptProposedAction();
    }

    void dropEvent(QDropEvent *e) override
    {
        auto urls = e->mimeData()->urls();
        if (!urls.isEmpty())
        {
            m_filePath = urls.first().toLocalFile();
            m_fileEdit->setText(m_filePath);
            m_passwordEdit->setFocus();
        }
    }

private:
    void browse()
    {
        QString path = QFileDialog::getOpenFileName(this, "Ouvrir un fichier chiffré",
                                                    QString(),
                                                    "Fichiers chiffrés (*.eloane *.e-zo);;Fichiers Eloane (*.eloane);;Fichiers E-ZO (*.e-zo);;Tous (*)");
        if (!path.isEmpty())
        {
            m_filePath = path;
            m_fileEdit->setText(path);
            m_passwordEdit->setFocus();
        }
    }

    void decrypt()
    {
        if (m_filePath.isEmpty())
        {
            showStatus("Veuillez sélectionner un fichier .eloane ou .e-zo", false);
            return;
        }
        if (m_passwordEdit->text().isEmpty())
        {
            showStatus("Veuillez entrer le mot de passe", false);
            return;
        }

        m_decryptBtn->setEnabled(false);
        m_decryptBtn->setText("Déchiffrement...");

        bool ok = false;
        QString result = EloaneDecrypt::decrypt(m_filePath, m_passwordEdit->text(), ok);

        m_decryptBtn->setEnabled(true);
        m_decryptBtn->setText("Déchiffrer");

        if (ok)
        {
            m_decryptedData = result;
            m_contentEdit->setPlainText(result);
            m_exportBtn->setEnabled(true);
            showStatus("Déchiffrement réussi", true);
        }
        else
        {
            m_contentEdit->clear();
            m_exportBtn->setEnabled(false);
            m_decryptedData.clear();
            showStatus(result, false);
        }
    }

    void exportJson()
    {
        if (m_decryptedData.isEmpty())
            return;
        QString path = QFileDialog::getSaveFileName(this, "Exporter en JSON",
                                                    m_filePath + ".json", "JSON (*.json);;Tous (*)");
        if (path.isEmpty())
            return;

        QFile f(path);
        if (f.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            f.write(m_decryptedData.toUtf8());
            f.close();
        }
        else
        {
            showStatus("Erreur d'écriture : " + path, false);
            return;
        }

// Forcer lecture seule (cross-platform)
#ifdef Q_OS_WIN
        std::wstring wpath = path.toStdWString();
        DWORD attrs = GetFileAttributesW(wpath.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES)
            SetFileAttributesW(wpath.c_str(), attrs | FILE_ATTRIBUTE_READONLY);
#else
        QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::ReadGroup | QFileDevice::ReadOther);
#endif

        showStatus("JSON exporté (lecture seule) : " + path, true);
    }

    void showStatus(const QString &msg, bool success)
    {
        m_statusLabel->setText(msg);
        m_statusLabel->setStyleSheet(success
                                         ? "color: #27ae60; font-weight: bold; padding: 4px;"
                                         : "color: #e74c3c; font-weight: bold; padding: 4px;");
    }

    QString m_filePath;
    QString m_decryptedData;
    QLineEdit *m_fileEdit;
    QLineEdit *m_passwordEdit;
    QPushButton *m_decryptBtn;
    QPushButton *m_exportBtn;
    QTextEdit *m_contentEdit;
    QLabel *m_statusLabel;
};

// ═══════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("EloaneDecryptor");
    app.setOrganizationName("Eloane");

    // Si un fichier est passé en argument (double-clic association)
    QString initialFile;
    if (argc >= 2)
    {
        initialFile = QString::fromLocal8Bit(argv[1]);
    }

    DecryptorWindow window(initialFile);
    window.show();

    // Centrer sur l'écran
    window.setGeometry(
        QStyle::alignedRect(Qt::LeftToRight, Qt::AlignCenter,
                            window.size(), window.screen()->availableGeometry()));

    return app.exec();
}
