# frida-java-menu
<p align="center">
<b>Easy library to create menu for Android using <a href="https://frida.re/">Frida</a></b></p>

![](https://i.imgur.com/gWrXy04.png)

<p align="center"><a href="https://github.com/commonuserlol/frida-java-menu/wiki/Examples"><b>Get started</b></a></p>

# Comparison
| *                        |     Android-Mod-Menu aka LGL Mod Menu     | Frida-Java-Menu |
|:------------------------:|:-----------------------------------------:|:---------------:|
|JNI knowledge required    |✅                                         |❌               |
|Change config at runtime  |❌                                         |✅               |
|Easy to inject            |❌ (need to add smali manually)            |✅               |
|Dymanically add widgets   |❌ (hardcoded in `GetFeatureList`)         |✅               |
|Easy create widget        |❌ (args splitted by "_")                  |✅               |
|Easy callbacks            |❌ (by index)                              |✅ (by function) |
|Editor/IDE tips with types|✅ (not for widgets)                       |✅               |


# Supported roms
Should work with (almost) pure **AOSP** (e.g. **LineageOS** based rom)<br>
Correct work is ***NOT GUARANTEED*** for MIUI, EMUI, RUI and other **OEM** rom<br>

# Credits

[Frida](https://github.com/frida/frida/) - make this possible<br>
[Android-Mod-Menu](https://github.com/LGLTeam/Android-Mod-Menu/) - original project<br>
[frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge/) - useful internal things

# Need help?
Use wiki (rarely updates) or create issue