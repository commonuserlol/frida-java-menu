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

    export function button(text?: string, callback?: (this: Button) => void, longCallback?: (this: Button) => void): Button {
        const context = Menu.instance.context;
        const button = new Button(context, text);
        const params = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Api.MATCH_PARENT);
        params.setMargins(7, 5, 7, 5);
        button.layoutParams = params;
        button.allCaps = false;
        button.textColor = Menu.instance.theme.secondaryTextColor;
        button.backgroundColor = Menu.instance.theme.buttonColor;
        if (callback) button.onClickListener = () => callback.call(button);
        if (longCallback) button.onLongClickListener = () => longCallback.call(button);

        return button;
    }
}