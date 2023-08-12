namespace Menu {
    export class Button extends Object {
        constructor(context: Java.Wrapper, text?: string) {
            super(context);
            this.instance = Api.Button.$new(context);
            if (text) this.text = text;
        }
        /* Gets is all symbols caps */
        get allCaps(): boolean {
            return !!this.instance.isAllCaps();
        }
        /** Sets is all symbols caps */
        set allCaps(allCaps: boolean) {
            this.instance.setAllCaps(allCaps);
        }
    }

    export function button(context: Java.Wrapper, text?: string, callback?: () => void, longCallback?: () => void): Button {
        const button = new Button(context, text);
        if (callback) button.onClickListener = callback;
        if (longCallback) button.onLongClickListener = longCallback;

        return button;
    }
}