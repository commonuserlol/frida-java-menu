namespace Menu {
    export class Layout extends Object {
        public static LinearLayoutParams = (a: Java.Wrapper | number, b: Java.Wrapper | number) => Api.LinearLayout_Params.$new(this.arguments);
        public static RelativeLayoutParams = (a: Java.Wrapper | number, b: Java.Wrapper | number) => Api.RelativeLayout_Params.$new(this.arguments);

        constructor(type: Java.Wrapper) {
            super(context);
            this.instance = type.$new(context);
        }
        get childCount(): number {
            return this.instance.getChildCount();
        }
        set verticalGravity(verticalGravity: number) {
            this.instance.setVerticalGravity(verticalGravity);
        }
        child(index: number): Java.Wrapper | null {
            return this.instance.getChildAt(index);
        }
        override destroy() {
            sleep().then(() => {
                for (let i = 0; i < this.childCount; i++) {
                    this.child(i)!.$dispose();
                }
                (this as Object).destroy();
            });
        }
    }
}