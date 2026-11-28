# Detect It Easy CLI (optional obf_lvl voter)

The voter shells out to the official `diec`. Binaries and the signature
database are **not** committed. The verified setup is DIE 4.1.0 on Fedora 45:

1. Download the official Fedora 45 RPM from `horsicq/DIE-engine` (Beta/Beta
   release) and extract it (do not install system-wide):

   ```bash
   mkdir -p ~/.local/opt/asyncparser-die/die_extract
   cd ~/.local/opt/asyncparser-die/die_extract
   rpm2cpio /path/to/DetectItEasy_4.1.0_fedora_45_amd64.rpm | cpio -idm
   ```

2. Download the Fedora 45 Qt5 runtime and extract it:

   ```bash
   mkdir -p ~/.local/opt/asyncparser-die/qt5rpms
   dnf download --destdir ~/.local/opt/asyncparser-die/qt5rpms \
     --forcearch=x86_64 qt5-qtbase qt5-qtscript
   mkdir -p ~/.local/opt/asyncparser-die/qt5root
   cd ~/.local/opt/asyncparser-die/qt5root
   for rpm in ../qt5rpms/*.x86_64.rpm; do rpm2cpio "$rpm" | cpio -idm; done
   ```

3. Download and extract the `current-database` `db.zip` from
   `horsicq/Detect-It-Easy` into `~/.local/opt/asyncparser-die/die_db/`.

4. Wrapper `~/.local/opt/asyncparser-die/diec`:

   ```bash
   #!/bin/bash
   BASE="$HOME/.local/opt/asyncparser-die"
   export LD_LIBRARY_PATH="$BASE/qt5root/usr/lib64:$BASE/die_extract/usr/lib64"
   exec "$BASE/die_extract/usr/bin/diec" -D "$BASE/die_db/db" "$@"
   ```

5. Check and run:

   ```bash
   ~/.local/opt/asyncparser-die/diec --version   # die 4.1.0
   python3 Tools/Voters/DIE/die_voter.py \
     --diec ~/.local/opt/asyncparser-die/diec
   ```

If `diec` is unavailable the voter records `obf_lvl=unknown`; never fake it.
