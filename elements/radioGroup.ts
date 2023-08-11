namespace Menu {
    export class RadioGroup extends Object {
        private label: TextView;
        private theme: Theme;
        private unformattedText: string;
        
        constructor(context: Java.Wrapper, text: string, theme: Theme) {
            super(context);
            this.instance = Api.RadioGroup.$new(context);
            this.theme = theme;
            this.label = new TextView(context, text);
            let params = Api.LinearLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            this.unformattedText = text;
            this.label.text = format(text, 0);
            this.instance.addView(Java.cast(this.label.instance, Api.View), 0, params);
        }
        /**
         * Gets orientation
         *
         * @type {number}
         */
        get orientation(): number {
            return this.instance.getOrientation();
        }
        /**
         * Sets orientation
         *
         * @type {number}
         */
        set orientation(orientation: number) {
            this.instance.setOrientation(orientation);
        }
        /**
         * Adds new `RadioButton`
         *
         * @public
         * @param {string} label button text
         * @param {number} index button index
         * @param {?(index: number) => void} [callback]
         */
        public addButton(label: string, index: number, callback?: (index: number) => void) {
            let button = new Object(this.context);
            let params = Api.LinearLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            button.instance = Api.RadioButton.$new(this.context);
            button.text = label;
            button.textColor = this.theme.secondaryTextColor;
            if (callback) {
                button.onClickListener = () => {
                    this.label.text = format(this.unformattedText, label);
                    callback(index);
                }
            }
            this.instance.addView(Java.cast(button.instance, Api.View), index+1, params);
        }
        /**
         * Checks object with given id
         *
         * @public
         * @param {number} id
         */
        public check(id: number) {
            this.label.text = format(this.unformattedText, Java.cast(this.instance.findViewById(id), Api.TextView).getText().toString());
            this.instance.check(id);
        }
        /**
         * Gets child at ginen index
         *
         * @public
         * @param {number} index
         * @returns {Java.Wrapper}
         */
        public getChildAt(index: number): Java.Wrapper {
            return this.instance.getChildAt(index);
        }
    }
}