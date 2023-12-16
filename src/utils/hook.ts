namespace Menu {
    /** @internal */
    export function hook(name: string, callback?: ((instance: Java.Wrapper) => void), overload?: string) {
        const target = overload ? Api.Activity[name].overload(overload) : Api.Activity[name];
        callback ? target.implementation = function (this: Java.Wrapper, args: any) {
            if (this.getComponentName().getClassName() == launcher) {
                callback?.(this);
            }
            args ? target.call(this, args) : target.call(this);
        } : target.implementation = null;
    }

    /** @internal */
    export function onPause(callback?: (() => void)) {
        hook("onPause", callback);
    }

    /** @internal */
    export function onResume(callback?: (() => void)) {
        hook("onResume", callback);
    }

    /** @internal */
    export function onDestroy(callback?: (() => void)) {
        hook("onDestroy", callback);
    }
}