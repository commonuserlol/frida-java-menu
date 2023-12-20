namespace Menu {
    export class Button extends View {
        constructor(text?: string) {
            super();
            this.instance = Api.Button.$new(app.context);
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

    /** @internal Initializes new `android.widget.Button` wrapper with default parameters */
    export function button(label: string, callback?: ThisCallback<Button>, longCallback?: ThisCallback<Button>) {
        const button = new Button(label);
        if (callback) button.onClickListener = callback as ThisCallback<View>;
        if (longCallback) button.onLongClickListener = longCallback as ThisCallback<View>;

        return button;
    }
}
