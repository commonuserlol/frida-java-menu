namespace Menu {
    export abstract class MainActivity {

        /** @internal */
        static hook(name: string, callback: ((instance: Java.Wrapper) => void) | null, overload?: string) {
            const target = overload ? Api.Activity[name].overload(overload) : Api.Activity[name];
            callback == null ? target.implementation = null : target.implementation = function (this: Java.Wrapper, args: any) {
                if (this.getComponentName().getClassName() == launcher) {
                    callback(this);
                }
                args ? target.call(this, args) : target.call(this);
            }
        }

        /** @internal */
        static onCreate() {
            // This actually internal cuz called very early
            // And used only by `waitForInit` to get instance
            // So user shouldn't use it
            // Also this won't be async since only with `Interceptor.attach`
            // We can use async without `Promise`, so
            // Async part will be inside `waitForInit`

            this.hook("onCreate", (instance) => {
                if (!activityInstance) activityInstance = Java.retain(instance);
                else this.hook("onCreate", null); // Disable hook
            }, "android.os.Bundle");
        }

        /** Hooks `onPause` method */
        static onPause(callback: (() => void) | null) {
            this.hook("onPause", callback);
        }

        /** Hooks `onResume` method */
        static onResume(callback: (() => void) | null) {
            this.hook("onResume", callback);
        }

        /** Hooks `onDestroy` method */
        static onDestroy(callback: (() => void) | null) {
            this.hook("onDestroy", callback);
        }

        /** Waits until the application context is valid */
        static async waitForInit(callback: () => void): Promise<void> {
            return new Promise((resolve, reject) => {
                MainActivity.onCreate();
                const waitInterval = setInterval(() => {
                    if (!app.instance) return;
                    clearInterval(waitInterval);
                    resolve();
                    Java.perform(callback);
                }, 10);
            });
        }

        /** Gets app `MainActivity` instance */
        static async getActivityInstance(): Promise<Java.Wrapper> {
            return new Promise((resolve, reject) => {
                if (activityInstance) {
                    resolve(activityInstance);
                    return;
                }

                // `Java.choose` has strange behavior on 32 bit Android 6-7 roms (crash) (5 and 8 not tested)
                // sometimes an access violation accessing 0xAddr may occur on Android 12.1 (does .1 actually gives something or on just A12 same?)
                // A9 - strange behavior
                // so it will be used only as fallback
                Java.choose(Api.Activity.$className, {
                    onMatch: (instance) => {
                        if (instance.getComponentName().getClassName() == launcher) {
                            activityInstance = Java.retain(instance);
                            resolve(instance);
                            return "stop";
                        }
                    },
                    onComplete() {}
                });
            });
        }
    }
}