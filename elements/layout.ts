namespace Menu {
    export class Layout extends Object {

        constructor(context: Java.Wrapper, type: Java.Wrapper) {
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
            setTimeout(() => {
                for (let i = 0; i < this.childCount; i++) {
                    this.child(i)!.$dispose();
                }
                (this as Object).destroy();
            }, 100);
        }
    }
}