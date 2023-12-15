namespace Menu {
    export declare type SwitchCallback = (this: Switch, state: boolean) => void;

    export class Switch extends View {
        constructor(text?: string, state: boolean = false) {
            super();
            this.instance = Api.Switch.$new(app.context);
            if (text) this.text = text;
            this.checked = state;
        }
        /** Sets checked */
        set checked(checked: boolean) {
            this.instance.setChecked(checked);
        }
        /** Sets onCheckedChangeListener */
        set onCheckedChangeListener(callback: (state: boolean) => void) {
            this.instance.setOnCheckedChangeListener(Java.registerClass({
                name: randomString(35),
                implements: [Api.CompoundButton_OnCheckedChangeListener],
                methods: {
                    onCheckedChanged: (object: Java.Wrapper, state: boolean) => {
                        sharedPreferences.putBool(this.text, state);
                        callback.call(this, state);
                    }
                }
            }).$new());
        }
    }
}
