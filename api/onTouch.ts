import { randomString } from "../utils.js";
import { OnTouchListener, Activity, VISIBLE, GONE, ORIENTATION_LANDSCAPE } from "./java.js";
import { MainActivity } from "./mainActivity.js";

/**
 * Represents `OnTouchListener` Java class 
 * 
 * @class OnTouch
 * @typedef {OnTouch}
 */
export class OnTouch {
    private instance: Java.Wrapper;
    private windowManager: Java.Wrapper;
    private collapsedView: Java.Wrapper;
    private expandedView: Java.Wrapper;
    private rootFrame: Java.Wrapper
    private params: Java.Wrapper;
    private initialPosition: [number, number];
    private touchPosition: [number, number];
    private orientation: number;
    
    constructor(windowManager: Java.Wrapper, collapsedView: Java.Wrapper, expandedView: Java.Wrapper, rootFrame: Java.Wrapper, params: Java.Wrapper) {
        this.windowManager = windowManager;
        this.collapsedView = collapsedView;
        this.expandedView = expandedView;
        this.rootFrame = rootFrame;
        this.params = params;
        MainActivity.instance.getClassInstance().then((instance) => {
            if (instance) this.orientation = instance.getResources().getConfiguration().orientation.value;
            else this.orientation = 1;
        });

        this.instance = Java.registerClass({
            name: randomString(35),
            implements: [OnTouchListener],
            methods: {
                onTouch: (view: Java.Wrapper, event: Java.Wrapper) => {
                    switch(event.getAction()) {
                        case 0: //ACTION_DOWN
                            this.initialPosition = [Math.floor(this.params.x.value), Math.floor(this.params.y.value)];
                            this.touchPosition = [Math.floor(event.getRawX()), Math.floor(event.getRawY())];
                            return true;
                        case 1: //ACTION_UP
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
                        case 2:
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
            }
        }).$new();
    }
    public setUser(user: Java.Wrapper) {
        user.setOnTouchListener(this.instance);
    }
}