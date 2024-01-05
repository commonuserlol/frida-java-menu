namespace Menu {
    /** @internal */
    type InitialPosition = {
        x: number,
        y: number
    };

    /** @internal */
    type TouchPosition = {
        x: number,
        y: number
    };

    /** @internal */
    export class OnTouch {
        initialPosition: InitialPosition;
        touchPosition: TouchPosition;

        constructor(target: View) {
            this.initialPosition = {x: 0, y: 0};
            this.touchPosition = {x: 0, y: 0};

            target.onTouchListener = (v, e) => this.callback(v, e);
        }

        callback(view: Java.Wrapper, event: Java.Wrapper) {
            switch(event.getAction()) {
                case Api.ACTION_DOWN:
                    this.initialPosition.x = Math.floor(instance.layout.params.x.value);
                    this.initialPosition.y = Math.floor(instance.layout.params.y.value);

                    this.touchPosition.x = Math.floor(event.getRawX());
                    this.touchPosition.y = Math.floor(event.getRawY());
                    return true;
                case Api.ACTION_UP:
                    instance.layout.me.alpha = 1.;
                    instance.$icon.alpha = instance.$icon.instance.$className == Api.ImageView.$className ? 255 : 1.;

                    const [rawX, rawY] = [Math.floor(event.getRawX() - this.touchPosition.x), Math.floor(event.getRawX() - this.touchPosition.y)];
                    if (instance.$icon.visibility == Api.VISIBLE) {
                        if (app.orientation == Api.ORIENTATION_LANDSCAPE) {
                            instance.$icon.visibility = Api.GONE;
                            instance.layout.me.visibility = Api.VISIBLE;
                        }
                        else if (rawX < 10 && rawY < 10) {
                            instance.$icon.visibility = Api.GONE;
                            instance.layout.me.visibility = Api.VISIBLE;
                        }
                    }
                    return true;
                case Api.ACTION_MOVE:
                    instance.layout.me.alpha = 0.5;
                    instance.$icon.alpha = instance.$icon.instance.$className == Api.ImageView.$className ?
                            Math.round(config.icon.alpha / 2) : 0.5;

                    instance.layout.params.x.value = this.initialPosition.x + Math.floor(event.getRawX() - this.touchPosition.x);
                    instance.layout.params.y.value = this.initialPosition.y + Math.floor(event.getRawY() - this.touchPosition.y);
                    
                    Java.scheduleOnMainThread(() => {
                        app.windowManager.updateViewLayout(instance.rootFrame.instance, instance.layout.params);
                    })
                    return true;
                default:
                    return false;
            }
        }
    }
}
