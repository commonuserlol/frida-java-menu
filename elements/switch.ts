namespace Menu {
    export class Switch extends Object {
        constructor(context: Java.Wrapper, text?: string, state: boolean = false) {
            super(context);
            this.instance = Api.Switch.$new(context);
            if (text) this.text = text;
            this.checked = state;
        }
        /**
         * Sets checked
         *
         * @type {boolean}
         */
        set checked(checked: boolean) {
            this.instance.setChecked(checked);
        }
        /**
         * Sets onCheckedChangeListener
         *
         * @type {(state: boolean) => void}
         */
        set onCheckedChangeListener(callback: (state: boolean) => void) {
            this.instance.setOnCheckedChangeListener(Java.registerClass({
                name: randomString(35),
                implements: [Api.CompoundButton_OnCheckedChangeListener],
                methods: {
                    onCheckedChanged: (object: Java.Wrapper, state: boolean) => {
                        callback(state);
                    }
                }
            }).$new());
        }
    }
}
