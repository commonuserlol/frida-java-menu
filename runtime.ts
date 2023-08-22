/// <reference path="./api/java.ts" />
/// <reference path="./utils/lazy.ts" />
/// <reference path="./utils/getter.ts" />

namespace Menu {
    export declare const androidVersion: string;
    getter(Menu, "androidVersion", () => Java.androidVersion, lazy);

    export declare const apiLevel: number;
    getter(Menu, "apiLevel", () => Api.Build_VERSION.SDK_INT.value, lazy);

    export declare const app: Java.Wrapper;
    getter(Menu, "app", () => Api.ActivityThread.currentApplication(), lazy);

    export declare const context: Java.Wrapper;
    getter(Menu, "context", () => app.getApplicationContext(), lazy);

    export declare const launcher: Java.Wrapper;
    getter(Menu, "launcher", () => app.getPackageManager()
        .getLaunchIntentForPackage(app.getPackageName())
        .resolveActivityInfo(app.getPackageManager(), 0)
        .name
        .value, lazy);

}