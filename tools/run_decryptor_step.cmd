@echo off
wsl.exe bash -lc "cd /mnt/c/Pro/clientBE/BIOPULZ/IHM_SOFT/E-ZO_CONNECTED/Decryptor/tools && dos2unix tools/run_decryptor_rpi.sh 2>/dev/null; ./tools/run_decryptor_rpi.sh"
