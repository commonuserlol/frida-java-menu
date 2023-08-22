namespace Api {
    export class OnTouch {
        private initialPosition: [number, number];
        private touchPosition: [number, number];
        private orientation: number;
        
        private callback(view: Java.Wrapper, event: Java.Wrapper) {
            const menu = Menu.Menu.getInstance();
            
            switch(event.getAction()) {
                case ACTION_DOWN:
                    this.initialPosition = [Math.floor(this.params.x.value), Math.floor(this.params.y.value)];
                    this.touchPosition = [Math.floor(event.getRawX()), Math.floor(event.getRawY())];
                    return true;
                case ACTION_UP:
                    this.expandedView.setAlpha(1.);
                    this.collapsedView.setAlpha(1.);
                    let [rawX, rawY] = [Math.floor(event.getRawX() - this.touchPosition[0]), Math.floor(event.getRawX() - this.touchPosition[1])];
                    if (this.collapsedView.getVisibility() == VISIBLE) {
                        if (this.orientation == ORIENTATION_LANDSCAPE) {
                            this.collapsedView.setVisibility(GONE);
                            this.expandedView.setVisibility(VISIBLE);
                        }
                        else if (rawX < 10 && rawY < 10) {
                            this.collapsedView.setVisibility(GONE);
                            this.expandedView.setVisibility(VISIBLE);
                        }
                    }
                    return true;
                case ACTION_MOVE:
                    this.expandedView.setAlpha(0.5);
                    this.collapsedView.setAlpha(0.5);
                    this.params.x.value = this.initialPosition[0] + Math.floor(event.getRawX() - this.touchPosition[0])
                    this.params.y.value = this.initialPosition[1] + Math.floor(event.getRawY() - this.touchPosition[1])
                    Java.scheduleOnMainThread(() => {
                        this.windowManager.updateViewLayout(this.rootFrame, this.params);
                    })
                    return true;
                default:
                    return false;
            }
        }

        static attach(target: Menu.Object) {
            Menu.MainActivity.instance.getClassInstance().then((instance) => {
                let orientation = instance.getResources().getConfiguration().orientation.value ?? 1;
                target.onTouchListener = new OnTouch().callback;
            });
        }
    }
}