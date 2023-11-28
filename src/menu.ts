namespace Menu {
    /** `Composer` class instance */
    export declare let instance: Composer;
    /** Theme instance for `Composer` */
    export declare let theme: Theme;
    /** Shared Preferences storage. Feel free to store own values */
    export declare const sharedPreferences: SharedPreferences;

    getter(Menu, "sharedPreferences", () => new SharedPreferences(), lazy);
    
    export class Composer {
        rootFrame: Layout;
        iconView: Icon;
        template: Menu.Template.GenericTemplate;

        constructor (title: string, subtitle: string, template: Menu.Template.GenericTemplate) {
            Menu.instance = this;

            if (!overlay.check()) {
                overlay.ask();
                setTimeout(() => MainActivity.getActivityInstance().then((instance) => instance.finish()), 3000);
            }

            this.rootFrame = new Layout(Api.FrameLayout);
            this.template = template;
            this.template.icon = this.iconView;
            this.template.title.text = title;
            this.template.subtitle.text = subtitle;
            
            this.add(this.template.me, this.rootFrame);
            this.template.handleAdd(this.add);

            MainActivity.onDestroy(() => this.destroy());
            MainActivity.onPause(() => this.hide());
            MainActivity.onResume(() => this.show());
        }

        /**
         * Sets icon for menu
         *
         * @public
         * @param {string} value can be base64-encoded image or link (only for Web type)
         * @param {("Normal" | "Web")} [type="Normal"] Normal accepts only base64-encoded image. Web accepts links to images/gifs, etc
         */
        public icon(value: string, type: "Normal" | "Web" = "Normal") {
            Java.scheduleOnMainThread(() => {
                this.template.initializeIcon(value, type);
                this.iconView = this.template.icon;
                
                new OnTouch(this.rootFrame);
                new OnTouch(this.iconView);

                this.add(this.iconView, this.rootFrame);
            });
        }

        /** Sets menu settings */
        public settings(label: string, state: boolean = false): Layout {
            const settings = new Settings(label, state);
            settings.orientation = Api.VERTICAL;
            this.add(settings.settings, this.template.titleLayout);
            return settings;
        }

        /** Hides menu */
        public hide() {
            Java.scheduleOnMainThread(() => {
                try {
                    this.rootFrame.visibility = Api.GONE;
                    this.remove(this.rootFrame, app.windowManager);
                }
                catch (e) {
                    console.warn("Menu already destroyed, ignoring `destroy` call");
                }
            });
        }

        /** Disposes instance of `Composer` */
        destroy() {
            MainActivity.onPause(null);
            MainActivity.onResume(null);
            MainActivity.onDestroy(null);
            this.hide();
            this.rootFrame.destroy();
            //this.layout.destroy();
        }

        /** Shows menu */
        public show() {
            Java.scheduleOnMainThread(() => {
                try {
                    app.windowManager.addView(this.rootFrame.instance, this.template.params);
                    this.rootFrame.visibility = Api.VISIBLE;
                }
                catch (e) {
                    console.warn("Menu already showed, ignoring `show` call");
                }
            });
        }

        /**
         * Adds view to layout
         *
         * @public
         * @param {View} view to add
         * @param {?(Java.Wrapper | View)} [layout] for add. If not provided general layout will be used
         */
        public add(view: View, layout?: Java.Wrapper | View) {
            Java.scheduleOnMainThread(() => {
                const l = layout ?? this.template.layout;
                (l instanceof View ? l.instance : l).addView((view instanceof View ? view.instance : view));
            })
        }

        /**
         * Removes view from layout
         *
         * @public
         * @param {View} view to remove
         * @param {?(Java.Wrapper | View)} [layout] for remove. If not provided general layout will be used
         */
        public remove(view: View, layout?: Java.Wrapper | View) {
            Java.scheduleOnMainThread(() => {
                const l = layout ?? this.template.layout;
                (l instanceof View ? l.instance : l).removeView((view instanceof View ? view.instance: view));
            })
        }

        /** Creates button */
        button(text?: string, callback?: (this: Button) => void, longCallback?: (this: Button) => void): Button {
            const button = new Button(text);
            const params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
            params.setMargins(7, 5, 7, 5);
            button.layoutParams = params;
            button.allCaps = false;
            button.textColor = theme.secondaryTextColor;
            button.backgroundColor = theme.buttonColor;
            if (callback) button.onClickListener = () => callback.call(button);
            if (longCallback) button.onLongClickListener = () => longCallback.call(button);
    
            return button;
        }

        /** Creates switch (toggle) but in button widget with ON and OFF states */
        buttonOnOff(text?: string, state: boolean = false, callback?: (this: Button, state: boolean) => void, longCallback?: (this: Button) => void): Button {
            const button = this.button(text, function () {
                state = !state;
                this.backgroundColor = state ? theme.buttonOnOffOnColor : theme.buttonOnOffOffColor;
                this.text = state ? `${text}: ON` : `${text}: OFF`;
                callback?.call(this, state);
            }, longCallback);

            button.backgroundColor = state ? theme.buttonOnOffOnColor : theme.buttonOnOffOffColor;
            button.text = state ? `${text}: ON` : `${text}: OFF`;

            if (state) {
                state = !state; // Small hack
                button.instance.performClick();
            }

            return button;
        }

        /** Creates dialog */
        async dialog(title: string, message: string, positiveCallback?: (this: Dialog) => void, negativeCallback?: (this: Dialog) => void, view?: Java.Wrapper | View): Promise<Dialog> {
            //We can create a dialog only with an activity instance, the context is not suitable.
            const instance = await MainActivity.getActivityInstance();
            const dialog = new Dialog(instance, title, message);
            view ? (view instanceof View ? dialog.view = view.instance : dialog.view = view) : null;
            if (positiveCallback) dialog.setPositiveButton(positiveCallback)
            if (negativeCallback) dialog.setNegativeButton(negativeCallback);
    
            return dialog;
        }

        /** Creates radio group */
        radioGroup(label: string, buttons: string[], callback?: (this: RadioGroup, index: number) => void): RadioGroup {
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
        seekbar(label: string, max: number, min?: number, callback?: (this: SeekBar, progress: number) => void): View {
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
        spinner(items: string[], callback?: (this: Spinner, index: number) => void): Spinner {
            const spinner = new Spinner(items);
            const savedIndex = sharedPreferences.getInt(items.join());
            if (savedIndex > -1) Java.scheduleOnMainThread(() => spinner.selection = savedIndex);
            if (callback) spinner.onItemSelectedListener = callback;
            return spinner;
        }

        /** Creates switch */
        toggle(label: string, callback?: (this: Switch, state: boolean) => void): Switch {
            //switch keyword already used, so we borrow the name from lgl code
            const toggle = new Switch(label);
            const savedState = sharedPreferences.getBool(label);
            toggle.textColor = theme.secondaryTextColor;
            toggle.padding = [10, 5, 10, 5];
            if (callback) toggle.onCheckedChangeListener = callback;
            if (savedState) Java.scheduleOnMainThread(() => toggle.checked = savedState);
    
            return toggle;
        }

        /** Creates text view */
        textView(label: string): TextView {
            const textView = new TextView(label);
            textView.textColor = theme.secondaryTextColor;
            textView.padding = [10, 5, 10, 5];
    
            return textView;
        }

        /** Creates category */
        public category(label: string): TextView {
            const textView = this.textView(label);
            textView.backgroundColor = theme.categoryColor;
            textView.gravity = Api.CENTER;
            textView.padding = [0, 5, 0, 5];
            textView.typeface = Api.Typeface.DEFAULT_BOLD.value;
            return textView;
        }

        /** Creates dialog with asking number and shows it */
        public async inputNumber(title: string, max: number, positiveCallback?: (this: Dialog, result: number) => void, negativeCallback?: (this: Dialog) => void): Promise<void> {
            let view = Api.EditText.$new(app.context);
            if (max > 0) {
                view.setHint(Api.JavaString.$new(`Max value: ${max}`));
            }
            view.setInputType(Api.InputType.TYPE_CLASS_NUMBER.value);
            await this.dialog(title, "", function () {
                let result = parseFloat(Java.cast(view, Api.TextView).getText().toString());
                !Number.isNaN(result) ? positiveCallback?.call(this, result <= max ? result : max) : positiveCallback?.call(this, NaN);
            }, function () {
                negativeCallback?.call(this);
            }, view).then((d) => d.show());  
        }

        /** Creates dialog with asking string and shows it */
        public async inputText(title: string, hint?: string, positiveCallback?: (this: Dialog, result: string) => void, negativeCallback?: (this: Dialog) => void): Promise<void> {
            let view = Api.EditText.$new(app.context);
            if (hint) view.setHint(wrap(hint));
            await this.dialog(title, "", function () {
                const result = Java.cast(view, Api.TextView).getText().toString();
                positiveCallback?.call(this, result);
            }, function () {
                negativeCallback?.call(this);
            }, view).then((d) => d.show());     
        }

        /** Creates collapse */
        public collapse(label: string, state: boolean = false): [Layout, Layout] {
            let parentLayout = new Layout(Api.LinearLayout);
            let layout = new Layout(Api.LinearLayout);
            let textView = this.category(`▽ ${label} ▽`);
            let params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
            textView.backgroundColor = theme.collapseColor;
            params.setMargins(0, 5, 0, 0);
            parentLayout.layoutParams = params;
            parentLayout.verticalGravity = 16;
            parentLayout.orientation = Api.VERTICAL;

            layout.verticalGravity = 16;
            layout.padding = [0, 5, 0, 5];
            layout.orientation = Api.VERTICAL;
            layout.backgroundColor = theme.layoutColor;
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

    /** Backwards compatible name with the new one.
     * 
     * Please do NOT use it for new projects
     * 
     * It WILL be removed after a few versions */
    export class JavaMenu extends Composer {}
}
