@echo off
wsl.exe bash -lc "cd /mnt/c/Pro/clientBE/BIOPULZ/IHM_SOFT/E-ZO_CONNECTED/Decryptor/tools && dos2unix tools/build_decryptor_on_rpi.sh 2>/dev/null; ./tools/build_decryptor_on_rpi.sh"
