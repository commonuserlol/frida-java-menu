namespace Menu {
    export declare const instance: JavaMenu;
    export class JavaMenu {

        context: Java.Wrapper;
        sharedPrefs: Api.SharedPreferences;
        windowManager: Java.Wrapper;
        theme: Theme;

        expandedView: Layout;
        iconView: Object;
        layout: Layout;
        menuParams: Java.Wrapper;
        rootFrame: Layout;
        scrollView: Layout;
        titleLayout: Layout;

        constructor (title: string, subtitle: string, theme: Theme) {
            getter(Menu, "instance", () => this);

            this.context = globalThis.Menu.context;
            this.theme = theme;
            if (!checkOverlayPermission(this.context)) {
                toast(this.context, this.theme.noOverlayPermissionText, 1);
                requestOverlayPermission(this.context);
                throw Error("No permission provided! Aborting...");
            }
            this.sharedPrefs = new Api.SharedPreferences(this.context);
            this.windowManager = Java.retain(Java.cast(this.context.getSystemService(Api.WINDOW_SERVICE), Api.ViewManager));
            this.rootFrame = new Layout(this.context, Api.FrameLayout);
            this.menuParams = Api.WindowManager_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT, getApiLevel() >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value, 8, -3); 
            this.expandedView = new Layout(this.context, Api.LinearLayout);
            this.layout = new Layout(this.context, Api.LinearLayout);
            this.titleLayout = new Layout(this.context, Api.RelativeLayout);
            this.scrollView = new Layout(this.context, Api.ScrollView);
            let titleText = new TextView(this.context, title);
            let titleParams = Api.RelativeLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            let subtitleText = new TextView(this.context, subtitle);
            let scrollParams = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Math.floor(dp(this.context, this.theme.menuHeight)));
            let buttonView = Api.RelativeLayout.$new(this.context);
            let hideButtonParams = Api.RelativeLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            let hideButton = new Button(this.context);
            let closeButtonParams = Api.RelativeLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            let closeButton = new Button(this.context);
            
            this.menuParams.gravity.value = 51;
            this.menuParams.x.value = this.theme.menuXPosition;
            this.menuParams.y.value = this.theme.menuYPosition;
            
            this.expandedView.visibility = Api.GONE;
            this.expandedView.backgroundColor = this.theme.bgColor;
            this.expandedView.orientation = Api.VERTICAL;
            this.expandedView.layoutParams = Api.LinearLayout_Params.$new(Math.floor(dp(this.context, this.theme.menuWidth)), Api.WRAP_CONTENT);
            
            this.titleLayout.padding = [10, 5, 10, 5];
            this.titleLayout.verticalGravity = 16;
            
            titleText.textColor = this.theme.primaryTextColor;
            titleText.textSize = 18;
            titleText.gravity = Api.CENTER;
            
            titleParams.addRule(Api.CENTER_HORIZONTAL);
            titleText.layoutParams = titleParams;
            
            subtitleText.ellipsize = Api.TruncateAt.MARQUEE.value;
            subtitleText.marqueeRepeatLimit = -1;
            subtitleText.singleLine = true;
            subtitleText.selected = true;
            subtitleText.textColor = this.theme.primaryTextColor;
            subtitleText.textSize = 10;
            subtitleText.gravity = Api.CENTER;
            subtitleText.padding = [0, 0, 0, 5];
            
            this.scrollView.layoutParams = scrollParams;
            this.scrollView.backgroundColor = this.theme.layoutColor;
            this.layout.orientation = Api.VERTICAL;
            
            buttonView.setPadding(10, 3, 10, 3);
            buttonView.setVerticalGravity(Api.CENTER);
            
            hideButtonParams.addRule(Api.ALIGN_PARENT_LEFT);
            hideButton.layoutParams = hideButtonParams;
            hideButton.backgroundColor = Api.TRANSPARENT;
            hideButton.text = this.theme.hideButtonText;
            hideButton.textColor = this.theme.primaryTextColor;
            hideButton.onClickListener = () => {
                this.iconView.visibility = Api.VISIBLE;
                this.iconView.alpha = 0;
                this.expandedView.visibility = Api.GONE;
                toast(this.context, this.theme.iconHiddenText, 1);
            }

            hideButton.onLongClickListener = () => {
                this.destroy();
                toast(this.context, this.theme.killText, 1);
            }

            closeButtonParams.addRule(Api.ALIGN_PARENT_RIGHT);
            closeButton.layoutParams = closeButtonParams;
            closeButton.backgroundColor = 0;
            closeButton.text = this.theme.closeText;
            closeButton.textColor = this.theme.primaryTextColor;
            closeButton.onClickListener = () => {
                this.iconView.visibility = Api.VISIBLE;
                this.iconView.alpha = this.theme.iconAlpha;
                this.expandedView.visibility = Api.GONE;
            }
            
            this.add(this.expandedView, this.rootFrame);
            this.add(titleText, this.titleLayout);
            this.add(this.titleLayout, this.expandedView);
            this.add(subtitleText, this.expandedView);
            this.add(this.layout, this.scrollView);
            this.add(this.scrollView, this.expandedView);
            this.add(hideButton, buttonView);
            this.add(closeButton, buttonView);
            this.add(buttonView, this.expandedView);

            MainActivity.instance.onDestroy = () => {
                this.destroy();
            };
            MainActivity.instance.onPause = () => {
                this.hide();
            };
            MainActivity.instance.onResume = () => {
                this.show();
            };
        }

        /**
         * Sets icon for menu
         *
         * @public
         * @param {string} value can be base64-encoded image or link (only for Web type)
         * @param {("Normal" | "Web")} [type="Normal"] Normal accepts only base64-encoded image. Web accepts links to images/gifs, etc
         */
        public icon(value: string, type: "Normal" | "Web" = "Normal"): void {
            Java.scheduleOnMainThread(() => {
                this.iconView = new Object(this.context);
                switch (type) {
                    case "Normal":
                        this.iconView.instance = Api.ImageView.$new(this.context);
                        this.iconView.instance.setScaleType(Api.ScaleType.FIT_XY.value);
                        this.iconView.onClickListener = () => {
                            this.iconView.visibility = Api.GONE;
                            this.expandedView.visibility = Api.VISIBLE;
                        }
                        this.iconView.instance.setImageBitmap(bitmap(value));
                        break;
                    case "Web":
                        this.iconView.instance = Api.WebView.$new(this.context);
                        this.iconView.instance.loadData(`<html><head></head><body style=\"margin: 0; padding: 0\"><img src=\"${value}\" width=\"${this.theme.iconSize}\" height=\"${this.theme.iconSize}\" ></body></html>`, "text/html", "utf-8");
                        this.iconView.backgroundColor = Api.TRANSPARENT;
                        this.iconView.instance.setAlpha(this.theme.iconAlpha);
                        this.iconView.instance.getSettings().setAppCacheEnabled(true);
                        break;
                    default:
                        throw Error("Unsupported icon type!");
                }
                this.iconView.layoutParams = Api.LinearLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
                let applyDimension = Math.floor(dp(this.context, this.theme.iconSize));
                this.iconView.instance.getLayoutParams().height.value = applyDimension;
                this.iconView.instance.getLayoutParams().width.value = applyDimension;
                this.iconView.alpha = this.theme.iconAlpha;
                this.iconView.visibility = Api.VISIBLE;
                
                new OnTouch(this.rootFrame);
                new OnTouch(this.iconView);

                this.add(this.iconView, this.rootFrame);
            });
        }

        /**
         * Sets menu settings
         *
         * @public
         * @param {string} text 
         * @param {boolean} state
         * @returns {Java.Wrapper}
         */
        public settings(text: string, state: boolean): Layout {
            let settings = new TextView(this.context, text);
            let settingsView = Api.LinearLayout.$new(this.context);
            settingsView.orientation = Api.VERTICAL;
            settings.textColor = this.theme.primaryTextColor;
            settings.typeface = Api.Typeface.DEFAULT_BOLD.value;
            settings.textSize = 20;
            let settingsParams = Api.RelativeLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            settingsParams.addRule(Api.ALIGN_PARENT_RIGHT);
            settings.layoutParams = settingsParams;
            if (state) {
                this.remove(this.layout, this.scrollView);
                this.add(settingsView, this.scrollView);
            }
            settings.onClickListener = () => {
                state = !state;
                if (state) {
                    this.remove(this.layout, this.scrollView);
                    this.add(settingsView, this.scrollView);
                }
                else {
                    this.remove(settingsView, this.scrollView);
                    this.add(this.layout, this.scrollView);
                }
            }
            this.add(settings, this.titleLayout);
            return settingsView;
        }

        /**
         * Hides menu
         *
         * @public
         */
        public hide(): void {
            Java.scheduleOnMainThread(() => {
                try {
                    this.rootFrame.visibility = Api.GONE;
                    this.remove(this.rootFrame, this.windowManager);
                }
                catch (e) {
                    console.warn("Menu already destroyed, ignoring `destroy` call");
                }
            });
        }

        destroy() {
            MainActivity.instance.onPause = null;
            MainActivity.instance.onResume = null;
            MainActivity.instance.onDestroy = null;
            this.hide();
            this.rootFrame.destroy();
            this.layout.destroy();
        }

        /**
         * Shows menu
         *
         * @public
         */
        public show(): void {
            Java.scheduleOnMainThread(() => {
                try {
                    this.windowManager.addView(this.rootFrame.instance, this.menuParams);
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
         * @param {(Java.Wrapper | Object)} view to add
         * @param {?Java.Wrapper} [layout] for add. If not provided general layout will be used
         */
        public add(view: Java.Wrapper | Object, layout?: Java.Wrapper | Object): void {
            Java.scheduleOnMainThread(() => {
                const l = layout ?? this.layout;
                (l instanceof Object ? l.instance : l).addView((view instanceof Object ? view.instance : view));
            })
        }

        /**
         * Removes view from layout
         *
         * @public
         * @param {(Java.Wrapper | Object)} view to remove
         * @param {?Java.Wrapper} [layout] for remove. If not provided general layout will be used
         */
        public remove(view: Java.Wrapper | Object, layout?: Java.Wrapper | Object): void {
            Java.scheduleOnMainThread(() => {
                const l = layout ?? this.layout;
                (l instanceof Object ? l.instance : l).removeView((view instanceof Object ? view.instance : view));
            })
        }

        button(text?: string, callback?: (this: Button) => void, longCallback?: (this: Button) => void): Button {
            const button = new Button(context, text);
            const params = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Api.MATCH_PARENT);
            params.setMargins(7, 5, 7, 5);
            button.layoutParams = params;
            button.allCaps = false;
            button.textColor = Menu.instance.theme.secondaryTextColor;
            button.backgroundColor = Menu.instance.theme.buttonColor;
            if (callback) button.onClickListener = () => callback.call(button);
            if (longCallback) button.onLongClickListener = () => longCallback.call(button);
    
            return button;
        }

        async dialog(title: string, message: string, positiveCallback?: (this: Dialog) => void, negativeCallback?: (this: Dialog) => void, view?: Java.Wrapper | Object): Promise<Dialog> {
            //We can create a dialog only with an activity instance, the context is not suitable.
            const instance = await MainActivity.instance.getClassInstance();
            const dialog = new Dialog(instance, title, message);
            view ? (view instanceof Object ? dialog.view = view.instance : dialog.view = view) : null;
            if (positiveCallback) dialog.setPositiveButton(positiveCallback)
            if (negativeCallback) dialog.setNegativeButton(negativeCallback);
    
            return dialog;
        }

        radioGroup(label: string, buttons: string[], callback: (this: RadioGroup, index: number) => void): RadioGroup {
            const context = Menu.instance.context;
            const radioGroup = new RadioGroup(context, label, Menu.instance.theme);
            const savedIndex = Menu.instance.sharedPrefs.getInt(label);
            radioGroup.padding = [10, 5, 10, 5];
            radioGroup.orientation = Api.VERTICAL;
            for (const button of buttons) {
                const index = buttons.indexOf(button);
                radioGroup.addButton(button, index, callback);
            }
            Java.scheduleOnMainThread(() => radioGroup.check(radioGroup.getChildAt(savedIndex+1).getId()));
    
            return radioGroup;
        }

        seekbar(label: string, max: number, min?: number, callback?: (this: SeekBar, progress: number) => void): Object {
            const add = Menu.instance.add;
            const context = Menu.instance.context;
            const seekbar = new SeekBar(context, label, Menu.instance.sharedPrefs.getInt(label));
            const layout = new Object(context);
            layout.instance = Api.LinearLayout.$new(context);
            layout.layoutParams = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Api.MATCH_PARENT);
            layout.orientation = Api.VERTICAL;
            seekbar.padding = [25, 10, 35, 10];
            seekbar.max = max;
            min ? seekbar.min = min : seekbar.min = 0;
            if (callback) seekbar.onSeekBarChangeListener = callback;
    
            add(seekbar.label, layout.instance);
            add(seekbar, layout.instance);
    
            return layout;
        }

        spinner(items: string[], callback?: (this: Spinner, index: number) => void): Spinner {
            const context = Menu.instance.context;
            const spinner = new Spinner(context, items, Menu.instance.theme);
            const savedIndex = Menu.instance.sharedPrefs.getInt(items.join());
            if (callback) spinner.onItemSelectedListener;
            if (savedIndex != -1) Java.scheduleOnMainThread(() => spinner.selection = savedIndex);
    
            return spinner;
        }

        toggle(label: string, callback?: (this: Switch, state: boolean) => void): Switch {
            //switch keyword already used, so we borrow the name from lgl code
            const context = Menu.instance.context;
            const toggle = new Switch(context, label);
            const savedState = Menu.instance.sharedPrefs.getBool(label);
            toggle.textColor = Menu.instance.theme.secondaryTextColor;
            toggle.padding = [10, 5, 10, 5];
            if (callback) toggle.onCheckedChangeListener = callback;
            if (savedState) Java.scheduleOnMainThread(() => toggle.checked = savedState);
    
            return toggle;
        }

        textView(label: string): TextView {
            const context = Menu.instance.context;
            const textView = new TextView(context, label);
            textView.textColor = Menu.instance.theme.secondaryTextColor;
            textView.padding = [10, 5, 10, 5];
    
            return textView;
        }

        /**
         * Creates category
         *
         * @public
         * @param {string} text
         * @returns {TextView}
         */
        public category(text: string): TextView {
            const label = this.textView(text);
            label.backgroundColor = this.theme.categoryColor;
            label.gravity = Api.CENTER;
            label.padding = [0, 5, 0, 5];
            label.typeface = Api.Typeface.DEFAULT_BOLD.value;
            return label;
        }

        public async inputNumber(title: string, max: number, positiveCallback?: (this: Dialog, result: number) => void, negativeCallback?: (this: Dialog) => void): Promise<void> {
            let view = Api.EditText.$new(this.context);
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

        public async inputText(title: string, hint?: string, positiveCallback?: (this: Dialog, result: string) => void, negativeCallback?: (this: Dialog) => void): Promise<void> {
            let view = Api.EditText.$new(context);
            if (hint) view.setHint(wrap(hint));
            await this.dialog(title, "", function () {
                const result = Java.cast(view, Api.TextView).getText().toString();
                positiveCallback?.call(this, result);
            }, function () {
                negativeCallback?.call(this);
            }, view).then((d) => d.show());     
        }

        /**
         * Creates collapse
         *
         * @public
         * @param {string} text
         * @param {boolean} state
         * @returns {[Java.Wrapper, Java.Wrapper]}
         */
        public collapse(text: string, state: boolean): [Java.Wrapper, Java.Wrapper] {
            let parentLayout = Api.LinearLayout.$new(this.context);
            let layout = Api.LinearLayout.$new(this.context);
            let label = this.category(`▽ ${text} ▽`);
            let params = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Api.MATCH_PARENT);
            label.backgroundColor = this.theme.collapseColor;
            params.setMargins(0, 5, 0, 0);
            parentLayout.setLayoutParams(params);
            parentLayout.setVerticalGravity(16);
            parentLayout.setOrientation(Api.VERTICAL);

            layout.setVerticalGravity(16);
            layout.setPadding(0, 5, 0, 5);
            layout.setOrientation(Api.VERTICAL);
            layout.setBackgroundColor(this.theme.layoutColor);
            layout.setVisibility(Api.GONE);

            label.padding = [0, 20, 0, 20];
            if (state) {
                layout.setVisibility(Api.VISIBLE);
                label.text = `△ ${text} △`;
            }
            label.onClickListener = () => {
                state = !state;
                if (state) {
                    layout.setVisibility(Api.VISIBLE);
                    label.text = `△ ${text} △`;
                }
                else {
                    layout.setVisibility(Api.GONE);
                    label.text = `▽ ${text} ▽`;
                }
            }
            this.add(label, parentLayout);
            this.add(layout, parentLayout);
            return [parentLayout, layout];
        }
    }
}
