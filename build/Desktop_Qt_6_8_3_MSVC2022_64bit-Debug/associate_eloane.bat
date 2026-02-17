@echo off
:: ═══════════════════════════════════════════════════════════
:: associate_eloane.bat — Associer les .eloane à EloaneDecryptor
:: Exécuter en tant qu'Administrateur
:: ═══════════════════════════════════════════════════════════

set DECRYPTOR_PATH=%~dp0EloaneDecryptor.exe

if not exist "%DECRYPTOR_PATH%" (
    echo ERREUR: EloaneDecryptor.exe non trouvé dans le dossier courant.
    echo Placez ce script dans le meme dossier que EloaneDecryptor.exe
    pause
    exit /b 1
)

echo Association des fichiers .eloane avec EloaneDecryptor...
echo Chemin: %DECRYPTOR_PATH%

:: Créer l'association de type de fichier
reg add "HKCU\Software\Classes\.eloane" /ve /d "EloaneFile" /f
reg add "HKCU\Software\Classes\EloaneFile" /ve /d "Fichier Eloane chiffré" /f
reg add "HKCU\Software\Classes\EloaneFile\shell\open\command" /ve /d "\"%DECRYPTOR_PATH%\" \"%%1\"" /f

echo.
echo Terminé ! Les fichiers .eloane s'ouvriront maintenant avec EloaneDecryptor.
echo Double-cliquez sur un fichier .eloane pour le tester.
pause
