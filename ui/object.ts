namespace Menu {
    export class Object {
        public context: Java.Wrapper;
        public instance: Java.Wrapper;

        public constructor (context?: Java.Wrapper, handleOrInstance?: NativePointerValue | Java.Wrapper) {
            // Context holder still required in case if this object will represent dialog
            // Which actually uses activity instance, not context
            // But context is nested class of activity
            // So idk should i rename `context` to `activity`...
            this.context = context ?? app.context;
            handleOrInstance ? this.instance = Java.cast(handleOrInstance, Api.View) : null;
        }
        /** Gets alpha */
        get alpha() {
            return this.instance.getAlpha();
        }
        /** Gets background */
        get background(): Java.Wrapper {
            return this.instance.getBackground();
        }
        /** Gets layout params */
        get layoutParams(): Java.Wrapper {
            return this.instance.getLayoutParams();
        }
        /** Gets orientation */
        get orientation(): number {
            return this.instance.getOrientation();
        }
        /** Gets padding */
        get padding(): number[] {
            return [this.instance.getPaddingLeft(), this.instance.getPaddingTop(), this.instance.getPaddingRight(), this.instance.getPaddingBottom()];
        }
        /** Gets text */
        get text(): string {
            return Java.cast(this.instance, Api.TextView).getText().toString();
        }
        /** Gets text color */
        get textColor(): Java.Wrapper {
            return this.instance.getTextColors();
        }
        /** Gets visibility */
        get visibility(): number {
            return this.instance.getVisibility();
        }
        /** Sets alpha */
        set alpha(alpha: number) {
            this.instance.setAlpha(alpha);
        }
        /** Sets background color */
        set backgroundColor(color: Java.Wrapper | number) {
            this.instance.setBackgroundColor(color);
        }
        /** Sets layout params */
        set layoutParams(params: Java.Wrapper) {
            this.instance.setLayoutParams(params);
        }
        /** Sets orientation */
        set orientation(orientation: number) {
            this.instance.setOrientation(orientation);
        }
        /** Sets padding */
        set padding(position: [left: number, top: number, right: number, bottom: number]) {
            this.instance.setPadding(...position);
        }
        /** Sets text */
        set text(text: string) {
            this.instance.setText(wrap(text));
        }
        /** Sets text color */
        set textColor(color: Java.Wrapper | number) {
            this.instance.setTextColor(color);
        }
        /** Sets visibility */
        set visibility(visibility: number) {
            this.instance.setVisibility(visibility);
        }
        /** Sets onClickListener callback */
        set onClickListener(callback: () => void) {
            this.instance.setOnClickListener(Java.registerClass({
                name: randomString(35),
                implements: [Api.OnClickListener],
                methods: {
                    onClick: callback
                }
            }).$new());
        }
        /** Sets onLongClickListener callback */
        set onLongClickListener(callback: () => void) {
            this.instance.setOnLongClickListener(Java.registerClass({
                name: randomString(35),
                implements: [Api.OnLongClickListener],
                methods: {
                    onLongClick: (view: Java.Wrapper) => {
                        callback();
                        return true;
                    }
                }
            }).$new());
        }
        /** Sets onTouchListener callback */
        set onTouchListener(callback: (view: Java.Wrapper, event: Java.Wrapper) => void) {
            this.instance.setOnTouchListener(Java.registerClass({
                name: randomString(35),
                implements: [Api.OnTouchListener],
                methods: {
                    onTouch: callback
                }
            }).$new());
        }
        destroy() {
            sleep().then(() => this.instance.$dispose());
        }
    }
    
    export function wrap(text: string): Java.Wrapper
    {
        return Api.HTML.fromHtml(Api.JavaString.$new(String(text)));
    }
}