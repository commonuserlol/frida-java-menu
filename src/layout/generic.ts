namespace Menu {
    export declare type ComposerHandler = (view: View, layout?: Java.Wrapper | View) => void;

    /** Generic class for templates. Your template must extend this */
    export abstract class GenericLayout {
        /** Menu props */
        params: Java.Wrapper; // TODO: Maybe i should add wrapper for *params
        /** Layout as layout */
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

        constructor(cfg: GenericConfig) {
            config = cfg;
        }

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
        abstract handleAdd(add: ComposerHandler): void;

        /** Removes template objects */
        abstract handleRemove(remove: ComposerHandler): void;

        button(text?: string, callback?: ThisCallback<Button>, longCallback?: ThisCallback<Button>): Button {
            const button = new Button(text);
            if (callback) button.onClickListener = () => callback.call(button);
            if (longCallback) button.onLongClickListener = () => longCallback.call(button);
    
            return button;
        }

        async dialog(title: string, message: string, positiveCallback?: DialogCallback, negativeCallback?: DialogCallback, view?: Java.Wrapper | View): Promise<Dialog> {
            const instance = await MainActivity.getActivityInstance();
            const dialog = new Dialog(instance, title, message);
            view ? (view instanceof View ? dialog.view = view.instance : dialog.view = view) : null;
            if (positiveCallback) dialog.setPositiveButton(positiveCallback)
            if (negativeCallback) dialog.setNegativeButton(negativeCallback);
    
            return dialog;
        }

        radioGroup(label: string, buttons: string[], callback?: ThisWithIndexCallback<RadioGroup>): RadioGroup {
            const radioGroup = new RadioGroup(label);
            const savedIndex = sharedPreferences.getInt(label);
            for (const button of buttons) {
                const index = buttons.indexOf(button);
                radioGroup.addButton(button, index, callback);
            }
            if (savedIndex > -1) Java.scheduleOnMainThread(() => radioGroup.check(radioGroup.getChildAt(savedIndex+1).getId()));
    
            return radioGroup;
        }

        seekbar(label: string, max: number, min?: number, callback?: SeekBarCallback): View {
            const seekbar = new SeekBar(label, sharedPreferences.getInt(label));
            seekbar.max = max;
            min ? seekbar.min = min : seekbar.min = 0;
            if (callback) seekbar.onSeekBarChangeListener = callback;
    
            return seekbar;
        }

        spinner(items: string[], callback?: ThisWithIndexCallback<Spinner>): Spinner {
            const spinner = new Spinner(items);
            const savedIndex = sharedPreferences.getInt(items.join());
            if (savedIndex > -1) Java.scheduleOnMainThread(() => spinner.selection = savedIndex);
            if (callback) spinner.onItemSelectedListener = callback;
            return spinner;
        }

        toggle(label: string, callback?: SwitchCallback): Switch {
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

        async inputNumber(title: string, max: number, positiveCallback: DialogInputCallback<number>, negativeCallback: DialogCallback): Promise<Dialog> {
            let view = Api.EditText.$new(app.context);
            if (max > 0) {
                view.setHint(Api.JavaString.$new(`Max value: ${max}`));
            }
            view.setInputType(Api.InputType.TYPE_CLASS_NUMBER.value);

            return await this.dialog(title, "", {
                label: positiveCallback?.label,
                fn: function () {
                    let result = parseFloat(Java.cast(view, Api.TextView).getText().toString());
                    !Number.isNaN(result) ? positiveCallback?.fn.call(this, result <= max ? result : max) : positiveCallback?.fn.call(this, NaN);
                },
            },
            negativeCallback, view);
        }

        async inputText(title: string, positiveCallback: DialogInputCallback<string>, negativeCallback: DialogCallback, hint?: string): Promise<Dialog> {
            let view = Api.EditText.$new(app.context);
            if (hint) view.setHint(wrap(hint));
            return await this.dialog(title, "", {
                label: positiveCallback.label,
                fn: function () {
                    const result = Java.cast(view, Api.TextView).getText().toString();
                    positiveCallback?.fn.call(this, result);
                }
            }, negativeCallback, view);
        }

        abstract destroy(): void;
    }
}