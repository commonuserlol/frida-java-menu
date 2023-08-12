namespace Menu {
    export class Object {
        public context: Java.Wrapper;
        public instance: Java.Wrapper;

        public constructor (context: Java.Wrapper) {
            this.context = context;
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
        /** Sets onClickListener callback */
        set onClickListener(callback: () => void) {
            this.instance.setOnClickListener(Java.registerClass({
                name: randomString(35),
                implements: [Api.OnClickListener],
                methods: {
                    onClick: (view: Java.Wrapper) => {
                        callback();
                    }
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
    }
}