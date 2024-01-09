## Overview
Yet easy but powerful [Frida](https://frida.re) module to create custom floating menu on Android.

## Features
* Frida Integration: no need to compile the code and then inject it every time as you did with a completely Java menu
* Zero-knowledge about JNI: this project uses frida's convenient api instead of JNI
* Ready-to-use wrappers: even if you don’t know anything about Java, the project already includes wrappers for the API with minimal jsdoc
* Highly customizable: ready-made layouts/configs available or create your own

## Usage
Please refer to wiki page.

## Troubleshooting
Through a very unstable Java bridge (on which this works), we cannot guarantee that everything will work. Please, prefer roms with non/slightly modified ART code (AOSP forks mainly)<br>***MIUI, ColorOS and other OEM roms MAY work incorrect or won't work at all***

## Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License
This project is licensed under the GNU General Public License v3.0.

## Acknowledgments
[Android-Mod-Menu](https://github.com/LGLTeam/Android-Mod-Menu/) - lgl layout java source<br>
[frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge) - internal helpers (lazy, decorate, ...)
