namespace Menu {

    export class RadioGroup extends View {
        buttons: string[];

        constructor(buttons: string[]) {
            super();
            this.instance = Api.RadioGroup.$new(app.context);
            this.buttons = buttons;
        }
        /** Adds new `RadioButton` */
        public addButton(label: string, index: number, callback?: (index: number) => void) {
            let button = new View(Api.RadioButton.$new(app.context));
            let params = Api.LinearLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            button.text = label;
            button.textColor = config.color.secondaryText;
            if (callback) {
                button.onClickListener = () => {
                    sharedPreferences.putInt(this.buttons.join(), index);
                    callback.call(this, index);
                }
            }
            this.instance.addView(Java.cast(button.instance, Api.View), index, params);
        }
        /** Checks object with given id */
        public check(id: number) {
            this.instance.check(id);
        }
        /** Gets child at ginen index */
        public getChildAt(index: number): Java.Wrapper {
            return this.instance.getChildAt(index);
        }
    }

    /** @internal Initializes new `android.widget.RadioGroup` wrapper with default parameters */
    export function radioGroup(buttons: string[], callback?: ThisWithIndexCallback<RadioGroup>): RadioGroup {
        const radioGroup = new RadioGroup(buttons);
        const savedIndex = sharedPreferences.getInt(buttons.join());
        for (const button of buttons) {
            let index = buttons.indexOf(button);
            radioGroup.addButton(button, index, callback);
        }
        if (savedIndex > -1) Java.scheduleOnMainThread(() => radioGroup.check(radioGroup.getChildAt(savedIndex+1).getId()));

        return radioGroup;
    }
}
