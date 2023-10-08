namespace Menu {
    export class Switch extends Object {
        constructor(text?: string, state: boolean = false) {
            super(context);
            this.instance = Api.Switch.$new(context);
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
