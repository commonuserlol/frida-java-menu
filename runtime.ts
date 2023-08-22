/// <reference path="./api/java.ts" />
/// <reference path="./utils/lazy.ts" />
/// <reference path="./utils/getter.ts" />

namespace Menu {
    export const app = {

        get instance(): Java.Wrapper {
            return Api.ActivityThread.currentApplication();
        },

        get packageManager(): Java.Wrapper {
            return this.instance.getPackageManager();
        },

        get packageName(): string {
            return this.instance.getPackageName();
        },
        
        get context(): Java.Wrapper {
            return this.instance.getApplicationContext();
        },

        get orientation(): number {
            return this.instance.getResources().getConfiguration().orientation.value;
        }
    };
    export declare const androidVersion: string;
    getter(Menu, "androidVersion", () => Java.androidVersion, lazy);

    export declare const apiLevel: number;
    getter(Menu, "apiLevel", () => Api.Build_VERSION.SDK_INT.value, lazy);

    export declare const context: Java.Wrapper;
    getter(Menu, "context", () => app.context, lazy);

    export declare const launcher: Java.Wrapper;
    getter(Menu, "launcher", () => app.packageManager
        .getLaunchIntentForPackage(app.packageName)
        .resolveActivityInfo(app.packageManager, 0)
        .name
        .value, lazy);

    decorate(app, lazy);
}