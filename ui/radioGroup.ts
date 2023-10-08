namespace Menu {
    export class RadioGroup extends Object {
        private theme: Theme;
        private unformattedText: string;
        public readonly label: TextView;
        
        constructor(text: string, theme: Theme) {
            super(context);
            this.instance = Api.RadioGroup.$new(context);
            this.theme = theme;
            this.label = new TextView(text);
            let params = Api.LinearLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            this.unformattedText = text;
            this.label.text = format(text, 0);
            this.instance.addView(Java.cast(this.label.instance, Api.View), 0, params);
        }
        /** Adds new `RadioButton` */
        public addButton(label: string, index: number, callback?: (index: number) => void) {
            let button = new Object(this.context);
            let params = Api.LinearLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            button.instance = Api.RadioButton.$new(this.context);
            button.text = label;
            button.textColor = this.theme.secondaryTextColor;
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
}