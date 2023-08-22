namespace Menu {
    export declare const androidVersion: string;
    export declare const apiLevel: number;
    export declare const context: Java.Wrapper;

    getter(globalThis.Menu, "androidVersion", () => Java.androidVersion, lazy);
    getter(globalThis.Menu, "apiLevel", () => Api.Build_VERSION.SDK_INT.value, lazy);
    getter(globalThis.Menu, "context", () => Api.ActivityThread.currentApplication().getApplicationContext(), lazy);
}