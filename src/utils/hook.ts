namespace Menu {
    /** @internal */
    export function hook(name: string, callback?: ((instance: Java.Wrapper) => void)) {
        const target = Api.Activity[name];
        callback ? target.implementation = function (this: Java.Wrapper, args: any) {
            if (this.getComponentName().getClassName() == launcher) {
                callback?.(this);
            }
            args ? target.call(this, args) : target.call(this);
        } : target.implementation = null;
    }

    /** @internal */
    export function onPause(callback?: (EmptyCallback)) {
        hook("onPause", callback);
    }

    /** @internal */
    export function onResume(callback?: (EmptyCallback)) {
        hook("onResume", callback);
    }

    /** @internal */
    export function onDestroy(callback?: (EmptyCallback)) {
        hook("onDestroy", callback);
    }
}