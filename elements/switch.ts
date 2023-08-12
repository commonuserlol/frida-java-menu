namespace Menu {
    export class Switch extends Object {
        constructor(context: Java.Wrapper, text?: string, state: boolean = false) {
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
                        Menu.getInstance().sharedPrefs.putBool(this.text, state);
                        callback.call(this, state);
                    }
                }
            }).$new());
        }
    }

    export function toggle(context: Java.Wrapper, label: string, callback?: (this: Switch, state: boolean) => void): Switch {
        //switch keyword already used, so we borrow the name from lgl code
        const toggle = new Switch(context, label);
        const savedState = Menu.getInstance().sharedPrefs.getBool(label);
        toggle.textColor = Menu.getInstance().theme.secondaryTextColor;
        toggle.padding = [10, 5, 10, 5];
        if (callback) toggle.onCheckedChangeListener = callback;
        if (savedState) toggle.checked = savedState;

        return toggle;
    }
}
