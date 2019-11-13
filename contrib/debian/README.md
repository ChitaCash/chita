
Debian
====================
This directory contains files used to package chitad/chita-qt
for Debian-based Linux systems. If you compile chitad/chita-qt yourself, there are some useful files here.

## chita: URI support ##


chita-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install chita-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your chita-qt binary to `/usr/bin`
and the `../../share/pixmaps/chita128.png` to `/usr/share/pixmaps`

chita-qt.protocol (KDE)

