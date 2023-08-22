namespace Menu {
    export class TextView extends Object {
        constructor(context: Java.Wrapper, text: string) {
            super(context);
            this.instance = Api.TextView.$new(context);
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

    export function textView(label: string): TextView {
        const context = Menu.instance.context;
        const textView = new TextView(context, label);
        textView.textColor = Menu.instance.theme.secondaryTextColor;
        textView.padding = [10, 5, 10, 5];

        return textView;
    }
}
