/// <reference path="./api.ts" />
/// <reference path="./utils/lazy.ts" />
/// <reference path="./utils/getter.ts" />
/// <reference path="./utils/decorate.ts" />

namespace Menu {
    export const app = {
        /** Returns app instance */
        get instance(): Java.Wrapper {
            return Api.ActivityThread.currentApplication();
        },

        /** Returns package manager instance */
        get packageManager(): Java.Wrapper {
            return this.instance.getPackageManager();
        },

        /** Returns app package name */
        get packageName(): string {
            return this.instance.getPackageName();
        },
        
        /** Returns app context */
        get context(): Java.Wrapper {
            return this.instance.getApplicationContext();
        },

        /** Returns app orientation */
        get orientation(): number {
            return this.instance.getResources().getConfiguration().orientation.value;
        },

        /** Returns window manager instance */
        get windowManager(): Java.Wrapper {
            return Java.cast(app.context.getSystemService(Api.WINDOW_SERVICE), Api.ViewManager);
        }
    };

    export declare const activityInstance: Promise<Java.Wrapper>;
    getter(Menu, "activityInstance", () => {
        return new Promise((resolve, reject) => {
            Java.choose(Api.Activity.$className, {
                onMatch: (instance) => {
                    if (instance.getComponentName().getClassName() == launcher) {
                        resolve(Java.retain(instance));
                        return "stop";
                    }
                },
                onComplete() {}
            });
        });
    }, lazy);

    /** Android version */
    export declare const androidVersion: string;
    getter(Menu, "androidVersion", () => Java.androidVersion, lazy);

    /** Android API level */
    export declare const apiLevel: number;
    getter(Menu, "apiLevel", () => Api.Build_VERSION.SDK_INT.value, lazy);

    /** Determines main activity name */
    export declare const launcher: Java.Wrapper;
    getter(Menu, "launcher", () => app.packageManager
        .getLaunchIntentForPackage(app.packageName)
        .resolveActivityInfo(app.packageManager, 0)
        .name
        .value, lazy);
}
