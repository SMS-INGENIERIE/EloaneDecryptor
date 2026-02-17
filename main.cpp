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
#include <string>
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

namespace EloaneDecrypt {

constexpr int SALT_SIZE    = 16;
constexpr int AES_KEY_SIZE = 32;
constexpr int HMAC_KEY_SIZE= 32;
constexpr int IV_SIZE      = 16;
constexpr int HMAC_SIZE    = 32;
constexpr int MAGIC_SIZE   = 4;
constexpr int PBKDF2_ITER  = 600000;
constexpr char MAGIC[4]    = {'E','L','O',0x01};

bool deriveKeys(const QByteArray& pw, const unsigned char* salt,
                unsigned char* aesKey, unsigned char* hmacKey)
{
    unsigned char derived[64];
    if (PKCS5_PBKDF2_HMAC(pw.constData(), pw.size(), salt, SALT_SIZE,
                          PBKDF2_ITER, EVP_sha256(), 64, derived) != 1)
        return false;
    memcpy(aesKey,  derived, 32);
    memcpy(hmacKey, derived + 32, 32);
    OPENSSL_cleanse(derived, 64);
    return true;
}

QByteArray computeHmac(const unsigned char* key, const QByteArray& data)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key, HMAC_KEY_SIZE,
         reinterpret_cast<const unsigned char*>(data.constData()), data.size(), out, &len);
    return (len == HMAC_SIZE) ? QByteArray(reinterpret_cast<char*>(out), len) : QByteArray();
}

QString decrypt(const QString& filePath, const QString& password, bool& ok)
{
    ok = false;
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return "Impossible d'ouvrir le fichier.";

    QByteArray data = f.readAll();
    f.close();

    int minSize = MAGIC_SIZE + SALT_SIZE + HMAC_SIZE + IV_SIZE + 16;
    if (data.size() < minSize)
        return "Fichier trop petit ou invalide.";

    if (memcmp(data.constData(), MAGIC, MAGIC_SIZE) != 0)
        return "Ce n'est pas un fichier .eloane valide.";

    int off = MAGIC_SIZE;
    const unsigned char* salt = reinterpret_cast<const unsigned char*>(data.constData() + off);
    off += SALT_SIZE;
    QByteArray storedHmac = data.mid(off, HMAC_SIZE);
    off += HMAC_SIZE;
    QByteArray payload = data.mid(off);

    unsigned char aesKey[AES_KEY_SIZE], hmacKey[HMAC_KEY_SIZE];
    QByteArray pw = password.toUtf8();
    if (!deriveKeys(pw, salt, aesKey, hmacKey)) {
        OPENSSL_cleanse(aesKey, 32); OPENSSL_cleanse(hmacKey, 32);
        return "Erreur de dérivation de clé.";
    }

    QByteArray computed = computeHmac(hmacKey, payload);
    if (computed.isEmpty() || CRYPTO_memcmp(storedHmac.constData(), computed.constData(), HMAC_SIZE) != 0) {
        OPENSSL_cleanse(aesKey, 32); OPENSSL_cleanse(hmacKey, 32);
        return "Mot de passe incorrect ou fichier modifié.";
    }

    const unsigned char* iv = reinterpret_cast<const unsigned char*>(payload.constData());
    QByteArray ciphertext = payload.mid(IV_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    QByteArray plaintext(ciphertext.size() + 16, '\0');
    int len = 0, total = 0;
    bool decOk = true;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey, iv) != 1) decOk = false;
    if (decOk && EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &len,
                                   reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                                   ciphertext.size()) != 1) decOk = false;
    if (decOk) total = len;
    if (decOk && EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + len, &len) != 1) decOk = false;
    if (decOk) total += len;
    EVP_CIPHER_CTX_free(ctx);

    OPENSSL_cleanse(aesKey, 32);
    OPENSSL_cleanse(hmacKey, 32);

    if (!decOk)
        return "Erreur de déchiffrement.";

    plaintext.resize(total);
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
    DecryptorWindow(const QString& initialFile = {}, QWidget* parent = nullptr)
        : QWidget(parent), m_filePath(initialFile)
    {
        setWindowTitle("Eloane Decryptor");
        setMinimumSize(700, 500);
        setAcceptDrops(true);

        auto* mainLayout = new QVBoxLayout(this);
        mainLayout->setSpacing(12);
        mainLayout->setContentsMargins(20, 20, 20, 20);

        // ── Titre ──
        auto* title = new QLabel("Déchiffreur de fichiers Eloane");
        title->setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;");
        title->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(title);

        // ── Fichier ──
        auto* fileLayout = new QHBoxLayout();
        auto* fileLabel = new QLabel("Fichier :");
        m_fileEdit = new QLineEdit();
        m_fileEdit->setReadOnly(true);
        m_fileEdit->setPlaceholderText("Glissez un fichier .eloane ici ou cliquez Parcourir...");
        if (!m_filePath.isEmpty()) m_fileEdit->setText(m_filePath);

        auto* browseBtn = new QPushButton("Parcourir...");
        connect(browseBtn, &QPushButton::clicked, this, &DecryptorWindow::browse);

        fileLayout->addWidget(fileLabel);
        fileLayout->addWidget(m_fileEdit, 1);
        fileLayout->addWidget(browseBtn);
        mainLayout->addLayout(fileLayout);

        // ── Mot de passe ──
        auto* pwLayout = new QHBoxLayout();
        auto* pwLabel = new QLabel("Mot de passe :");
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
        auto* bottomLayout = new QHBoxLayout();
        m_exportBtn = new QPushButton("Exporter en JSON...");
        m_exportBtn->setEnabled(false);
        connect(m_exportBtn, &QPushButton::clicked, this, &DecryptorWindow::exportJson);
        bottomLayout->addStretch();
        bottomLayout->addWidget(m_exportBtn);
        mainLayout->addLayout(bottomLayout);

        // Focus sur le mot de passe si un fichier est déjà chargé
        if (!m_filePath.isEmpty()) {
            m_passwordEdit->setFocus();
        }
    }

protected:
    void dragEnterEvent(QDragEnterEvent* e) override {
        if (e->mimeData()->hasUrls()) e->acceptProposedAction();
    }

    void dropEvent(QDropEvent* e) override {
        auto urls = e->mimeData()->urls();
        if (!urls.isEmpty()) {
            m_filePath = urls.first().toLocalFile();
            m_fileEdit->setText(m_filePath);
            m_passwordEdit->setFocus();
        }
    }

private:
    void browse() {
        QString path = QFileDialog::getOpenFileName(this, "Ouvrir un fichier Eloane",
                                                    QString(), "Fichiers Eloane (*.eloane);;Tous (*)");
        if (!path.isEmpty()) {
            m_filePath = path;
            m_fileEdit->setText(path);
            m_passwordEdit->setFocus();
        }
    }

    void decrypt() {
        if (m_filePath.isEmpty()) {
            showStatus("Veuillez sélectionner un fichier .eloane", false);
            return;
        }
        if (m_passwordEdit->text().isEmpty()) {
            showStatus("Veuillez entrer le mot de passe", false);
            return;
        }

        m_decryptBtn->setEnabled(false);
        m_decryptBtn->setText("Déchiffrement...");

        bool ok = false;
        QString result = EloaneDecrypt::decrypt(m_filePath, m_passwordEdit->text(), ok);

        m_decryptBtn->setEnabled(true);
        m_decryptBtn->setText("Déchiffrer");

        if (ok) {
            m_decryptedData = result;
            m_contentEdit->setPlainText(result);
            m_exportBtn->setEnabled(true);
            showStatus("Déchiffrement réussi", true);
        } else {
            m_contentEdit->clear();
            m_exportBtn->setEnabled(false);
            m_decryptedData.clear();
            showStatus(result, false);
        }
    }

    void exportJson() {
        if (m_decryptedData.isEmpty()) return;
        QString path = QFileDialog::getSaveFileName(this, "Exporter en JSON",
                                                    m_filePath + ".json", "JSON (*.json);;Tous (*)");
        if (path.isEmpty()) return;

        QFile f(path);
        if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            f.write(m_decryptedData.toUtf8());
            f.close();
        } else {
            showStatus("Erreur d'écriture : " + path, false);
            return;
        }

        // Forcer lecture seule via Windows API
        std::wstring wpath = path.toStdWString();
        DWORD attrs = GetFileAttributesW(wpath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            showStatus("Erreur : fichier introuvable après écriture", false);
            return;
        }
        BOOL result = SetFileAttributesW(wpath.c_str(), attrs | FILE_ATTRIBUTE_READONLY);
        if (!result) {
            showStatus("Erreur : impossible de mettre en lecture seule (code " +
                           QString::number(GetLastError()) + ")", false);
            return;
        }

        showStatus("JSON exporté (lecture seule) : " + path, true);
    }

    void showStatus(const QString& msg, bool success) {
        m_statusLabel->setText(msg);
        m_statusLabel->setStyleSheet(success
                                         ? "color: #27ae60; font-weight: bold; padding: 4px;"
                                         : "color: #e74c3c; font-weight: bold; padding: 4px;");
    }

    QString m_filePath;
    QString m_decryptedData;
    QLineEdit* m_fileEdit;
    QLineEdit* m_passwordEdit;
    QPushButton* m_decryptBtn;
    QPushButton* m_exportBtn;
    QTextEdit* m_contentEdit;
    QLabel* m_statusLabel;
};

// ═══════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("EloaneDecryptor");
    app.setOrganizationName("Eloane");

    // Si un fichier est passé en argument (double-clic association)
    QString initialFile;
    if (argc >= 2) {
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
