namespace Menu {
    /** Switch JS callback */
    export declare type SwitchCallback = (this: Switch, state: boolean) => void;

    /** Wrapper for `android.widget.Switch` */
    export class Switch extends View {
        constructor(text?: string, state: boolean = false) {
            super();
            this.instance = Api.Switch.$new(app.context);
            if (text)
                this.text = text;
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

    /** @internal Initializes new `android.widget.Switch` wrapper with default parameters */
    export function toggle(label: string, callback?: SwitchCallback): Switch {
        const toggle = new Switch(label);
        if (callback)
            toggle.onCheckedChangeListener = callback;

        const savedState = sharedPreferences.getBool(label);
        if (savedState)
            Java.scheduleOnMainThread(() => toggle.checked = savedState);

        return toggle;
    }
}
