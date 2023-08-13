namespace Menu {
    export class MainActivity {
        public static instance: MainActivity;
        public static classInstance: Java.Wrapper;
        private readonly className: string;
        private readonly launcherIntent: Java.Wrapper;

        constructor() {
            let app = Api.ActivityThread.currentApplication();
            this.launcherIntent = app.getPackageManager().getLaunchIntentForPackage(app.getPackageName());
            this.className = this.launcherIntent.resolveActivityInfo(app.getPackageManager(), 0).name.value;
        }

        /**
         * Hooks `onCreate` method
         *
         * @internal
         * @type {() => void | null} callback which will be called when method triggered. If null it reverts original impl
         */
        static set onCreate(callback: (() => void ) | null) {
            if (callback == null) {
                Api.Activity.onCreate.overload("android.os.Bundle").implementation = null;
            }
            Api.Activity.onCreate.overload("android.os.Bundle").implementation = function(savedInstanceState: Java.Wrapper) {
                this.onCreate.overload("android.os.Bundle").call(this, savedInstanceState);
                callback?.();
                if (!MainActivity.classInstance) {
                    MainActivity.classInstance = Java.retain(this);
                    setTimeout(() => MainActivity.onCreate = null, 100);
                }
            }
        }

        /**
         * Hooks `onPause` method
         *
         * @internal
         * @type {() => void | null} callback which will be called when method triggered. If null it reverts original impl
         */
        set onPause(callback: (() => void ) | null) {
            if (callback == null) {
                Api.Activity.onPause.implementation = null;
            }
            let targetActivityName = this.className;
            Api.Activity.onPause.implementation = function() {
                if (this.getComponentName().getClassName() == targetActivityName) {
                    callback?.();
                }
                this.onPause();
            }
        }

        /**
         * Hooks `onResume` method
         *
         * @internal
         * @type {() => void | null} callback which will be called when method triggered. If null it reverts original impl
         */
        set onResume(callback: (() => void ) | null) {
            if (callback == null) {
                Api.Activity.onResume.implementation = null;
            }
            let targetActivityName = this.className;
            Api.Activity.onResume.implementation = function() {
                if (this.getComponentName().getClassName() == targetActivityName) {
                    callback?.();
                }
                this.onResume();
            }
        }

        /**
         * Hooks `onDestroy` method
         *
         * @internal 
         * @type {() => void | null} callback which will be called when method triggered. If null it reverts original impl
         */
        set onDestroy(callback: (() => void ) | null) {
            if (callback == null) {
                Api.Activity.onDestroy.implementation = null;
            }
            let targetActivityName = this.className;
            Api.Activity.onDestroy.implementation = function() {
                if (this.getComponentName().getClassName() == targetActivityName) {
                    callback?.();
                }
                this.onDestroy();
            }
        }

        /**
         * Waits until the application context is valid
         *
         * @public
         * @static
         * @async
         * @param {() => void} callback
         * @returns {Promise<void>}
         */
        public static async waitForContext(callback: () => void): Promise<void> {
            MainActivity.onCreate = () => {};
            return new Promise((resolve, reject) => {
                const waitInterval = setInterval(() => {
                    if (!Api.ActivityThread.currentApplication()) return;
                    if (!this.instance) this.instance = new MainActivity();
                    Java.perform(callback);
                    clearInterval(waitInterval);
                    resolve();
                }, 100);
            });
        }
        public async getClassInstance(): Promise<Java.Wrapper> {
            return new Promise((resolve, reject) => {
                if (MainActivity.classInstance) {
                    resolve(MainActivity.classInstance);
                    return;
                }
                //`Java.choose` has strange behavior on Android 6-7 (5 and 8 not tested)
                //sometimes an access violation accessing 0x152 may occur
                //so it will be used only as fallback
                Java.choose(Api.Activity.$className, {
                    onMatch: (instance) => {
                        if (instance.getComponentName().getClassName() == this.className) {
                            MainActivity.classInstance = Java.retain(instance);
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