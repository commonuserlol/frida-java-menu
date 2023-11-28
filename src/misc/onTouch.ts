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
                    this.initialPosition = [Math.floor(instance.template.params.x.value), Math.floor(instance.template.params.y.value)];
                    this.touchPosition = [Math.floor(event.getRawX()), Math.floor(event.getRawY())];
                    return true;
                case Api.ACTION_UP:
                    instance.template.me.alpha = 1.;
                    instance.iconView.alpha = instance.iconView.instance.$className == Api.ImageView.$className ? 255 : 1.;
                    let [rawX, rawY] = [Math.floor(event.getRawX() - this.touchPosition[0]), Math.floor(event.getRawX() - this.touchPosition[1])];
                    if (instance.iconView.visibility == Api.VISIBLE) {
                        if (app.orientation == Api.ORIENTATION_LANDSCAPE) {
                            instance.iconView.visibility = Api.GONE;
                            instance.template.me.visibility = Api.VISIBLE;
                        }
                        else if (rawX < 10 && rawY < 10) {
                            instance.iconView.visibility = Api.GONE;
                            instance.template.me.visibility = Api.VISIBLE;
                        }
                    }
                    return true;
                case Api.ACTION_MOVE:
                    instance.template.me.alpha = 0.5;
                    instance.iconView.alpha = instance.iconView.instance.$className == Api.ImageView.$className ?
                            Math.round(theme.iconAlpha / 2) : 0.5;
                    instance.template.params.x.value = this.initialPosition[0] + Math.floor(event.getRawX() - this.touchPosition[0])
                    instance.template.params.y.value = this.initialPosition[1] + Math.floor(event.getRawY() - this.touchPosition[1])
                    Java.scheduleOnMainThread(() => {
                        app.windowManager.updateViewLayout(instance.rootFrame.instance, instance.template.params);
                    })
                    return true;
                default:
                    return false;
            }
        }
    }
}
