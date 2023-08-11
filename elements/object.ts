namespace Menu {
    /**
     * Wrapper class for `View`
     *
     * @export
     * @class Object
     * @typedef {Object}
     */
    export class Object {
        public context: Java.Wrapper;
        public instance: Java.Wrapper;

        /**
         * Creates an instance of Object.
         *
         * @constructor
         * @public
         * @param {Java.Wrapper} context
         */
        public constructor (context: Java.Wrapper) {
            this.context = context;
        }
        /**
         * Gets background
         *
         * @readonly
         * @type {Java.Wrapper}
         */
        get background(): Java.Wrapper {
            return this.instance.getBackground();
        }
        /**
         * Gets layout params
         *
         * @type {Java.Wrapper}
         */
        get layoutParams(): Java.Wrapper {
            return this.instance.getLayoutParams();
        }
        /**
         * Gets padding
         *
         * @type {Array<number>} [left, top, right, bottom]
         */
        get padding(): Array<number> {
            return [this.instance.getPaddingLeft(), this.instance.getPaddingTop(), this.instance.getPaddingRight(), this.instance.getPaddingBottom()];
        }
        /**
         * Gets text
         *
         * @type {string}
         */
        get text(): string {
            return Java.cast(this.instance, Api.TextView).getText().toString();
        }
        /**
         * Gets text color
         *
         * @type {Java.Wrapper}
         */
        get textColor(): Java.Wrapper {
            return this.instance.getTextColors();
        }
        /**
         * Sets background color
         *
         * @type {*}
         */
        set backgroundColor(color: Java.Wrapper | number) {
            this.instance.setBackgroundColor(color);
        }
        /**
         * Sets layout params
         *
         * @type {*}
         */
        set layoutParams(params: Java.Wrapper) {
            this.instance.setLayoutParams(params);
        }
        /**
         * Sets padding
         *
         * @type {*}
         */
        set padding(position: [left: number, top: number, right: number, bottom: number]) {
            this.instance.setPadding(...position);
        }
        /**
         * Sets text
         *
         * @type {string}
         */
        set text(text: string) {
            this.instance.setText(wrap(text));
        }
        /**
         * Sets text color
         *
         * @type {*}
         */
        set textColor(color: Java.Wrapper | number) {
            this.instance.setTextColor(color);
        }
        /**
         * Sets onClickListener callback
         *
         * @type {() => void}
         */
        set onClickListener(callback: () => void) {
            this.instance.setOnClickListener(Java.registerClass({
                name: randomString(35),
                implements: [Api.OnClickListener],
                methods: {
                    onClick: function(view: Java.Wrapper) {
                        callback();
                    }
                }
            }).$new());
        }
        /**
         * Sets onLongClickListener callback
         *
         * @type {() => void}
         */
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