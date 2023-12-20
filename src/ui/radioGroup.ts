namespace Menu {

    export class RadioGroup extends View {
        private unformattedText: string;
        public readonly label: TextView;
        
        constructor(text: string) {
            super();
            this.instance = Api.RadioGroup.$new(app.context);
            this.label = new TextView(text);
            let params = Api.LinearLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            this.unformattedText = text;
            this.label.text = format(text, 0);
            this.instance.addView(Java.cast(this.label.instance, Api.View), 0, params);
        }
        /** Adds new `RadioButton` */
        public addButton(label: string, index: number, callback?: (index: number) => void) {
            let button = new View(Api.RadioButton.$new(app.context));
            let params = Api.LinearLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            button.text = label;
            button.textColor = config.color.secondaryText;
            if (callback) {
                button.onClickListener = () => {
                    this.label.text = format(this.unformattedText, label);
                    sharedPreferences.putInt(this.label.text, index);
                    callback(index);
                }
            }
            this.instance.addView(Java.cast(button.instance, Api.View), index+1, params);
        }
        /** Checks object with given id */
        public check(id: number) {
            this.label.text = format(this.unformattedText, Java.cast(this.instance.findViewById(id), Api.TextView).getText().toString());
            this.instance.check(id);
        }
        /** Gets child at ginen index */
        public getChildAt(index: number): Java.Wrapper {
            return this.instance.getChildAt(index);
        }
    }

    /** @internal Initializes new `android.widget.RadioGroup` wrapper with default parameters */
    export function radioGroup(label: string, buttons: string[], callback?: ThisWithIndexCallback<RadioGroup>): RadioGroup {
        const radioGroup = new RadioGroup(label);
        const savedIndex = sharedPreferences.getInt(label);
        for (const button of buttons) {
            const index = buttons.indexOf(button);
            radioGroup.addButton(button, index, callback);
        }
        if (savedIndex > -1) Java.scheduleOnMainThread(() => radioGroup.check(radioGroup.getChildAt(savedIndex+1).getId()));

        return radioGroup;
    }
}
