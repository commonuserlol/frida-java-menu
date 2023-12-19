namespace Menu {
    /** @internal */
    export class OnTouch {
        initialPosition: [number, number];
        touchPosition: [number, number];

        constructor(target: View) {
            this.initialPosition = [0, 0];
            this.touchPosition = [0, 0];

            target.onTouchListener = (v, e) => this.callback(v, e);
        }

        callback(view: Java.Wrapper, event: Java.Wrapper) {
            switch(event.getAction()) {
                case Api.ACTION_DOWN:
                    this.initialPosition = [Math.floor(instance.layout.params.x.value), Math.floor(instance.layout.params.y.value)];
                    this.touchPosition = [Math.floor(event.getRawX()), Math.floor(event.getRawY())];
                    return true;
                case Api.ACTION_UP:
                    instance.layout.me.alpha = 1.;
                    instance.layout.icon.alpha = instance.layout.icon.instance.$className == Api.ImageView.$className ? 255 : 1.;
                    let [rawX, rawY] = [Math.floor(event.getRawX() - this.touchPosition[0]), Math.floor(event.getRawX() - this.touchPosition[1])];
                    if (instance.layout.icon.visibility == Api.VISIBLE) {
                        if (app.orientation == Api.ORIENTATION_LANDSCAPE) {
                            instance.layout.icon.visibility = Api.GONE;
                            instance.layout.me.visibility = Api.VISIBLE;
                        }
                        else if (rawX < 10 && rawY < 10) {
                            instance.layout.icon.visibility = Api.GONE;
                            instance.layout.me.visibility = Api.VISIBLE;
                        }
                    }
                    return true;
                case Api.ACTION_MOVE:
                    instance.layout.me.alpha = 0.5;
                    instance.layout.icon.alpha = instance.layout.icon.instance.$className == Api.ImageView.$className ?
                            Math.round(config.icon.alpha / 2) : 0.5;
                    instance.layout.params.x.value = this.initialPosition[0] + Math.floor(event.getRawX() - this.touchPosition[0])
                    instance.layout.params.y.value = this.initialPosition[1] + Math.floor(event.getRawY() - this.touchPosition[1])
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
