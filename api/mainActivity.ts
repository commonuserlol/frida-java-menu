import { Activity, ActivityThread } from "./java.js";

/**
 * Wrapper class for `MainActivity` Java class
 *
 * @export
 * @class MainActivity
 * @typedef {MainActivity}
 */
export class MainActivity {
    public static instance: MainActivity;
    public static classInstance: Java.Wrapper;
    private className: string;
    private launcherIntent: Java.Wrapper;

    /**
     * Creates an instance of MainActivity.
     *
     * @constructor
     */
    constructor() {
        let app = ActivityThread.currentApplication();
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
            Activity.onCreate.overload("android.os.Bundle").implementation = null;
        }
        Activity.onCreate.overload("android.os.Bundle").implementation = function(savedInstanceState: Java.Wrapper) {
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
            Activity.onPause.implementation = null;
        }
        let targetActivityName = this.className;
        Activity.onPause.implementation = function() {
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
            Activity.onResume.implementation = null;
        }
        let targetActivityName = this.className;
        Activity.onResume.implementation = function() {
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
            Activity.onDestroy.implementation = null;
        }
        let targetActivityName = this.className;
        Activity.onDestroy.implementation = function() {
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
                if (!ActivityThread.currentApplication()) return;
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
            Java.choose(Activity.$className, {
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