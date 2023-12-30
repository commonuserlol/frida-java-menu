namespace Menu {
    /** Wrapper for `android.widget.*Layout` */
    export class Layout extends View {
        /** Creates `LinearLayout.LayoutParams` */
        static LinearLayoutParams = (a: Java.Wrapper | number, b: Java.Wrapper | number): Java.Wrapper => Api.LinearLayout_Params.$new(a, b);
        /** Creates `RelativeLayout.LayoutParams` */
        static RelativeLayoutParams = (a: Java.Wrapper | number, b: Java.Wrapper | number): Java.Wrapper => Api.RelativeLayout_Params.$new(a, b);

        constructor(type: Java.Wrapper) {
            super();
            this.instance = type.$new(app.context);
        }
        /** Returns layout child count */
        get childCount(): number {
            return this.instance.getChildCount();
        }
        set gravity(gravity: number) {
            this.instance.setGravity(gravity);
        }
        /** Sets vertical gravity */
        set verticalGravity(verticalGravity: number) {
            this.instance.setVerticalGravity(verticalGravity);
        }
        /** Gets child at specified index */
        child(index: number): Java.Wrapper | null {
            return this.instance.getChildAt(index);
        }
    }
}
