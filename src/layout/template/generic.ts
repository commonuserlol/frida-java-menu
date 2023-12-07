namespace Menu {
    export namespace Template {
        /** Generic class for templates. Your template must extend this */
        export abstract class GenericTemplate {
            /** Menu props */
            params: Java.Wrapper; // TODO: Maybe i should add wrapper for *params
            /** Template as layout */
            me: Layout;
            /** Icon holder */
            icon: Icon;
            /** Proxy layout for scrolling feature */
            proxy: Layout;
            /** Main layout for widgets */
            layout: Layout;
            /** Layout for title and settings */
            titleLayout: Layout;
            /** Title TextView */
            title: TextView;
            /** Subtitle TextView */
            subtitle: TextView;
            /** Layout for hide/kill and close buttons */
            buttonLayout: Layout;
            /** Hide/kill button */
            hide: Button;
            /** Close button */
            close: Button;

            constructor() {}

            /** Initializes menu props */
            abstract initializeParams(): void;

            /** Initializes own layout */
            abstract initializeLayout(): void;

            /** Initializes icon */
            abstract initializeIcon(value: string, type: "Normal" | "Web"): void;

            /** Initializes proxy layout for scrolling feature */
            abstract initializeProxy(): void;

            /** Initializes main layout for widgets */
            abstract initializeMainLayout(): void;

            /** Initializes hide/kill & close button and their layout */
            abstract initializeButtons(): void;

            /** Initializes everything needed for start
             * 
             * Called by constructor after title & subtitle init
             */
            abstract ensureInitialized(): void;

            /** Adds everything needed from template */
            abstract handleAdd(add: (view: View, layout?: Java.Wrapper | View) => void): void;

            /** Removes template objects */
            abstract handleRemove(remove: (view: View, layout?: Java.Wrapper | View) => void): void;

            button(text?: string, callback?: (this: Button) => void, longCallback?: (this: Button) => void): Button {
                const button = new Button(text);
                if (callback) button.onClickListener = () => callback.call(button);
                if (longCallback) button.onLongClickListener = () => longCallback.call(button);
        
                return button;
            }

            async dialog(title: string, message: string, positiveLabel: string = "OK", positiveCallback?: (this: Dialog) => void, negativeLabel: string = "Cancel", negativeCallback?: (this: Dialog) => void, view?: Java.Wrapper | View): Promise<Dialog> {
                const instance = await MainActivity.getActivityInstance();
                const dialog = new Dialog(instance, title, message);
                view ? (view instanceof View ? dialog.view = view.instance : dialog.view = view) : null;
                if (positiveCallback) dialog.setPositiveButton(positiveLabel, positiveCallback)
                if (negativeCallback) dialog.setNegativeButton(negativeLabel, negativeCallback);
        
                return dialog;
            }

            radioGroup(label: string, buttons: string[], callback?: (this: RadioGroup, index: number) => void): RadioGroup {
                const radioGroup = new RadioGroup(label);
                const savedIndex = sharedPreferences.getInt(label);
                for (const button of buttons) {
                    const index = buttons.indexOf(button);
                    radioGroup.addButton(button, index, callback);
                }
                if (savedIndex > -1) Java.scheduleOnMainThread(() => radioGroup.check(radioGroup.getChildAt(savedIndex+1).getId()));
        
                return radioGroup;
            }

            seekbar(label: string, max: number, min?: number, callback?: (this: SeekBar, progress: number) => void): View {
                const seekbar = new SeekBar(label, sharedPreferences.getInt(label));
                seekbar.max = max;
                min ? seekbar.min = min : seekbar.min = 0;
                if (callback) seekbar.onSeekBarChangeListener = callback;
        
                return seekbar;
            }

            spinner(items: string[], callback?: (this: Spinner, index: number) => void): Spinner {
                const spinner = new Spinner(items);
                const savedIndex = sharedPreferences.getInt(items.join());
                if (savedIndex > -1) Java.scheduleOnMainThread(() => spinner.selection = savedIndex);
                if (callback) spinner.onItemSelectedListener = callback;
                return spinner;
            }

            toggle(label: string, callback?: (this: Switch, state: boolean) => void): Switch {
                const toggle = new Switch(label);
                const savedState = sharedPreferences.getBool(label);
                if (callback) toggle.onCheckedChangeListener = callback;
                if (savedState) Java.scheduleOnMainThread(() => toggle.checked = savedState);
        
                return toggle;
            }

            textView(label: string): TextView {
                const textView = new TextView(label);
        
                return textView;
            }

            async inputNumber(title: string, max: number, positiveLabel: string, positiveCallback?: (this: Dialog, result: number) => void, negativeLabel?: string, negativeCallback?: (this: Dialog) => void): Promise<void> {
                let view = Api.EditText.$new(app.context);
                if (max > 0) {
                    view.setHint(Api.JavaString.$new(`Max value: ${max}`));
                }
                view.setInputType(Api.InputType.TYPE_CLASS_NUMBER.value);
                await this.dialog(title, "", positiveLabel, function () {
                    let result = parseFloat(Java.cast(view, Api.TextView).getText().toString());
                    !Number.isNaN(result) ? positiveCallback?.call(this, result <= max ? result : max) : positiveCallback?.call(this, NaN);
                }, negativeLabel, function () {
                    negativeCallback?.call(this);
                }, view).then((d) => d.show());
            }

            async inputText(title: string, hint?: string, positiveLabel?: string, positiveCallback?: (this: Dialog, result: string) => void, negativeLabel?: string, negativeCallback?: (this: Dialog) => void): Promise<void> {
                let view = Api.EditText.$new(app.context);
                if (hint) view.setHint(wrap(hint));
                await this.dialog(title, "", positiveLabel, function () {
                    const result = Java.cast(view, Api.TextView).getText().toString();
                    positiveCallback?.call(this, result);
                }, negativeLabel, function () {
                    negativeCallback?.call(this);
                }, view).then((d) => d.show());
            }

            abstract destroy(): void;
        }
    }
}