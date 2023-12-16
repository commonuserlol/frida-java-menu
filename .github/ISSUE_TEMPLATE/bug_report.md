---
name: Bug report
about: 'Create a bug report '
title: "[BUG]"
labels: bug
assignees: ''

---
**PLEASE COMPLETE THIS TEMPLATE OR ISSUE WILL BE CLOSED WITHOUT EXPLANATION**


**YOU MUST COMPLETE EVERYTHING WHICH NOT MARKED (optional)**


**Describe the bug**
A clear and concise description of what the bug is.


**Your frida script or part of it**
Please attach as file or paste and format via markdown like:
```typescript
here your script
```


**To Reproduce**
Steps to reproduce the behavior, like:
1. Compile script
2. Run frida with my script
3. Press button
4. Crash


**Expected behavior**
A clear and concise description of what you expected to happen, e.g.:
1. Compile script
2. Run frida with my script
3. Press button
4. Text on button changed

**Screenshots (optional)**
If applicable, add screenshots to help explain your problem, else skip or delete this.


**Backtrace (optional, complete this only if you got crash, else delete/skip)**
To get backtrace run connect to phone via adb, run app, run ASAP command: `adb shell pidof -s com.app.name` (Android 8+, replace com.app.name with real package name) OR try other from [here](https://stackoverflow.com/questions/6854127/filter-logcat-to-get-only-the-messages-from-my-application-in-android).


**Device**
 - Device name: [e.g. Xiaomi Redmi 10TS Pro Max]
 - Firmware or Custom ROM: [e.g. MIUI 14 or LineageOS 20]
 - Android version: [e.g. Android 12.1]

**Additional context (optional)**
Add any other context about the problem here.
