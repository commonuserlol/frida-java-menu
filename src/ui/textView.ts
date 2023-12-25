namespace Menu {
    /** Wrapper for `android.widget.TextView` */
    export class TextView extends View {
        constructor(text?: string) {
            super();
            this.instance = Api.TextView.$new(app.context);
            if (text)
                this.text = text;
        }
        /** Gets ellipsize */
        get ellipsize(): Java.Wrapper {
            return this.instance.getEllipsize();
        }
        /** Gets gravity */
        get gravity(): number {
            return this.instance.getGravity();
        }
        /** Gets marqueeRepeatLimit */
        get marqueeRepeatLimit(): number {
            return this.instance.getMarqueeRepeatLimit();
        }
        /** Gets text size */
        get textSize(): number {
            return this.instance.getTextSize();
        }
        /** Gets typeface */
        get typeface(): Java.Wrapper {
            return this.instance.getTypeface();
        }
        /** Sets ellipsize */
        set ellipsize(where: Java.Wrapper) {
            this.instance.setEllipsize(where);
        }
        /** Sets gravity */
        set gravity(gravity: number) {
            this.instance.setGravity(gravity);
        }
        /** Sets marqueeRepeatLimit */
        set marqueeRepeatLimit(limit: number) {
            this.instance.setMarqueeRepeatLimit(limit);
        }
        /** Sets selected */
        set selected(selected: boolean) {
            this.instance.setSelected(selected);    
        }
        /** Sets singleLine */
        set singleLine(singleLine: boolean) {
            this.instance.setSingleLine(singleLine);
        }
        /** Sets text size */
        set textSize(size: number) {
            this.instance.setTextSize(size);
        }
        /** Sets typeface */
        set typeface(tf: Java.Wrapper) {
            this.instance.setTypeface(tf);
        }
    }

    /** @internal Initializes new `android.widget.TextView` wrapper with default parameters */
    export function textView(label: string): TextView {
        const textView = new TextView(label);

        return textView;
    }
}
