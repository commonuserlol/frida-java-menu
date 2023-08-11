namespace Menu {
    /**
     * Wrapper for `TextView`
     *
     * @export
     * @class TextView
     * @typedef {TextView}
     * @extends {Object}
     */
    export class TextView extends Object {
        /**
         * Creates an instance of TextView.
         *
         * @constructor
         * @param {Java.Wrapper} context
         * @param {string} text
         */
        constructor(context: Java.Wrapper, text: string) {
            super(context);
            this.instance = Api.TextView.$new(context);
            this.text = text;
        }
        /**
         * Gets ellipsize
         *
         * @type {Java.Wrapper}
         */
        get ellipsize(): Java.Wrapper {
            return this.instance.getEllipsize();
        }
        /**
         * Gets gravity
         *
         * @type {number}
         */
        get gravity(): number {
            return this.instance.getGravity();
        }
        /**
         * Gets marqueeRepeatLimit
         *
         * @type {number}
         */
        get marqueeRepeatLimit(): number {
            return this.instance.getMarqueeRepeatLimit();
        }
        /**
         * Gets text size
         *
         * @type {number}
         */
        get textSize(): number {
            return this.instance.getTextSize();
        }
        /**
         * Gets typeface
         *
         * @type {Java.Wrapper}
         */
        get typeface(): Java.Wrapper {
            return this.instance.getTypeface();
        }
        /**
         * Sets ellipsize
         *
         * @type {*}
         */
        set ellipsize(where: Java.Wrapper) {
            this.instance.setEllipsize(where);
        }
        /**
         * Sets gravity
         *
         * @type {number}
         */
        set gravity(gravity: number) {
            this.instance.setGravity(gravity);
        }
        /**
         * Sets marqueeRepeatLimit
         *
         * @type {number}
         */
        set marqueeRepeatLimit(limit: number) {
            this.instance.setMarqueeRepeatLimit(limit);
        }
        /**
         * Sets selected
         *
         * @type {boolean}
         */
        set selected(selected: boolean) {
            this.instance.setSelected(selected);    
        }
        /**
         * Sets singleLine
         *
         * @type {boolean}
         */
        set singleLine(singleLine: boolean) {
            this.instance.setSingleLine(singleLine);
        }
        /**
         * Sets text size
         *
         * @type {number}
         */
        set textSize(size: number) {
            this.instance.setTextSize(size);
        }
        /**
         * Sets typeface
         *
         * @type {*}
         */
        set typeface(tf: Java.Wrapper) {
            this.instance.setTypeface(tf);
        }
    }
}
