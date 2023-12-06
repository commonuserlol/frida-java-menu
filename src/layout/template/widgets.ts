namespace Menu {
    export namespace Template {
        /** Widgets initialize functions */
        export namespace Widgets {
            /** Creates button */
            export function button(text?: string, callback?: (this: Button) => void, longCallback?: (this: Button) => void): Button {
                const button = new Button(text);
                const params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
                params.setMargins(7, 5, 7, 5);
                button.layoutParams = params;
                button.allCaps = false;
                button.textColor = config.secondaryTextColor;
                button.backgroundColor = config.buttonColor;
                if (callback) button.onClickListener = () => callback.call(button);
                if (longCallback) button.onLongClickListener = () => longCallback.call(button);
        
                return button;
            }

            /** Creates switch (toggle) but in button widget with ON and OFF states */
            export function buttonOnOff(text?: string, state: boolean = false, callback?: (this: Button, state: boolean) => void, longCallback?: (this: Button) => void): Button {
                const button = this.button(text, function () {
                    state = !state;
                    this.backgroundColor = state ? config.buttonOnOffOnColor : config.buttonOnOffOffColor;
                    this.text = state ? `${text}: ON` : `${text}: OFF`;
                    callback?.call(this, state);
                }, longCallback);

                button.backgroundColor = state ? config.buttonOnOffOnColor : config.buttonOnOffOffColor;
                button.text = state ? `${text}: ON` : `${text}: OFF`;

                if (state) {
                    state = !state; // Small hack
                    button.instance.performClick();
                }

                return button;
            }

            /** Creates dialog */
            export async function dialog(title: string, message: string, positiveLabel: string = "OK", positiveCallback?: (this: Dialog) => void, negativeLabel: string = "Cancel", negativeCallback?: (this: Dialog) => void, view?: Java.Wrapper | View): Promise<Dialog> {
                //We can create a dialog only with an activity instance, the context is not suitable.
                const instance = await MainActivity.getActivityInstance();
                const dialog = new Dialog(instance, title, message);
                view ? (view instanceof View ? dialog.view = view.instance : dialog.view = view) : null;
                if (positiveCallback) dialog.setPositiveButton(positiveLabel, positiveCallback)
                if (negativeCallback) dialog.setNegativeButton(negativeLabel, negativeCallback);
        
                return dialog;
            }

            /** Creates radio group */
            export function radioGroup(label: string, buttons: string[], callback?: (this: RadioGroup, index: number) => void): RadioGroup {
                const radioGroup = new RadioGroup(label);
                const savedIndex = sharedPreferences.getInt(label);
                radioGroup.padding = [10, 5, 10, 5];
                radioGroup.orientation = Api.VERTICAL;
                for (const button of buttons) {
                    const index = buttons.indexOf(button);
                    radioGroup.addButton(button, index, callback);
                }
                if (savedIndex > -1) Java.scheduleOnMainThread(() => radioGroup.check(radioGroup.getChildAt(savedIndex+1).getId()));
        
                return radioGroup;
            }

            /** Creates seekbar */
            export function seekbar(label: string, max: number, min?: number, callback?: (this: SeekBar, progress: number) => void): View {
                const seekbar = new SeekBar(label, sharedPreferences.getInt(label));
                const layout = new View();
                layout.instance = Api.LinearLayout.$new(app.context);
                layout.layoutParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
                layout.orientation = Api.VERTICAL;
                seekbar.padding = [25, 10, 35, 10];
                seekbar.max = max;
                min ? seekbar.min = min : seekbar.min = 0;
                if (callback) seekbar.onSeekBarChangeListener = callback;
        
                this.add(seekbar.label, layout);
                this.add(seekbar, layout);
        
                return layout;
            }

            /** Creates spinner */
            export function spinner(items: string[], callback?: (this: Spinner, index: number) => void): Spinner {
                const spinner = new Spinner(items);
                const savedIndex = sharedPreferences.getInt(items.join());
                if (savedIndex > -1) Java.scheduleOnMainThread(() => spinner.selection = savedIndex);
                if (callback) spinner.onItemSelectedListener = callback;
                return spinner;
            }

            /** Creates switch */
            export function toggle(label: string, callback?: (this: Switch, state: boolean) => void): Switch {
                //switch keyword already used, so we borrow the name from lgl code
                const toggle = new Switch(label);
                const savedState = sharedPreferences.getBool(label);
                toggle.textColor = config.secondaryTextColor;
                toggle.padding = [10, 5, 10, 5];
                if (callback) toggle.onCheckedChangeListener = callback;
                if (savedState) Java.scheduleOnMainThread(() => toggle.checked = savedState);
        
                return toggle;
            }

            /** Creates text view */
            export function textView(label: string): TextView {
                const textView = new TextView(label);
                textView.textColor = config.secondaryTextColor;
                textView.padding = [10, 5, 10, 5];
        
                return textView;
            }

            /** Creates category */
            export function public category(label: string): TextView {
                const textView = this.textView(label);
                textView.backgroundColor = config.categoryColor;
                textView.gravity = Api.CENTER;
                textView.padding = [0, 5, 0, 5];
                textView.typeface = Api.Typeface.DEFAULT_BOLD.value;
                return textView;
            }

            /** Creates dialog with asking number and shows it */
            export async function inputNumber(title: string, max: number, positiveLabel: string = "OK", positiveCallback?: (this: Dialog, result: number) => void, negativeLabel: string = "Cancel", negativeCallback?: (this: Dialog) => void): Promise<void> {
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

            /** Creates dialog with asking string and shows it */
            export async function inputText(title: string, hint?: string, positiveLabel: string = "OK", positiveCallback?: (this: Dialog, result: string) => void, negativeLabel: string = "Cancel", negativeCallback?: (this: Dialog) => void): Promise<void> {
                let view = Api.EditText.$new(app.context);
                if (hint) view.setHint(wrap(hint));
                await this.dialog(title, "", positiveLabel, function () {
                    const result = Java.cast(view, Api.TextView).getText().toString();
                    positiveCallback?.call(this, result);
                }, negativeLabel, function () {
                    negativeCallback?.call(this);
                }, view).then((d) => d.show());     
            }

            /** Creates collapse */
            export function collapse(label: string, state: boolean = false): [Layout, Layout] {
                let parentLayout = new Layout(Api.LinearLayout);
                let layout = new Layout(Api.LinearLayout);
                let textView = this.category(`▽ ${label} ▽`);
                let params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
                textView.backgroundColor = config.collapseColor;
                params.setMargins(0, 5, 0, 0);
                parentLayout.layoutParams = params;
                parentLayout.verticalGravity = 16;
                parentLayout.orientation = Api.VERTICAL;

                layout.verticalGravity = 16;
                layout.padding = [0, 5, 0, 5];
                layout.orientation = Api.VERTICAL;
                layout.backgroundColor = config.layoutColor;
                layout.visibility = Api.GONE;

                textView.padding = [0, 20, 0, 20];
                textView.onClickListener = () => {
                    state = !state;
                    if (state) {
                        layout.visibility = Api.VISIBLE;
                        textView.text = `△ ${label} △`;
                    }
                    else {
                        layout.visibility = Api.GONE;
                        textView.text = `▽ ${label} ▽`;
                    }
                }
                if (state) {
                    state = !state; // Small hack
                    textView.instance.performClick();
                }
                this.add(textView, parentLayout);
                this.add(layout, parentLayout);
                return [parentLayout, layout];
            }
        }
    }
}