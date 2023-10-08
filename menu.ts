namespace Menu {
    export declare let instance: JavaMenu;
    export declare let theme: Theme;
    
    export class JavaMenu {

        sharedPrefs: Api.SharedPreferences;
        expandedView: Layout;
        iconView: Object;
        layout: Layout;
        menuParams: Java.Wrapper;
        rootFrame: Layout;
        scrollView: Layout;
        titleLayout: Layout;

        constructor (title: string, subtitle: string, theme: Theme) {
            Menu.instance = this;
            Menu.theme = theme;

            if (!overlay.check()) {
                overlay.ask();
                setTimeout(() => MainActivity.instance.getActivityInstance().then((instance) => instance.finish()), 3000);
            }

            this.sharedPrefs = new Api.SharedPreferences();
            this.rootFrame = new Layout(Api.FrameLayout);
            this.menuParams = Api.WindowManager_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT, apiLevel >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value, 8, -3); 
            this.expandedView = new Layout(Api.LinearLayout);
            this.layout = new Layout(Api.LinearLayout);
            this.titleLayout = new Layout(Api.RelativeLayout);
            this.scrollView = new Layout(Api.ScrollView);
            let titleText = new TextView(title);
            let titleParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            let subtitleText = new TextView(subtitle);
            let scrollParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Math.floor(dp(Menu.theme.menuHeight)));
            let buttonView = new Layout(Api.RelativeLayout);
            let hideButtonParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            let hideButton = new Button(Menu.theme.hideButtonText);
            let closeButtonParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            let closeButton = new Button(Menu.theme.closeText);
            
            this.menuParams.gravity.value = 51;
            this.menuParams.x.value = Menu.theme.menuXPosition;
            this.menuParams.y.value = Menu.theme.menuYPosition;
            
            this.expandedView.visibility = Api.GONE;
            this.expandedView.backgroundColor = Menu.theme.bgColor;
            this.expandedView.orientation = Api.VERTICAL;
            this.expandedView.layoutParams = Layout.LinearLayoutParams(Math.floor(dp(Menu.theme.menuWidth)), Api.WRAP_CONTENT);
            
            this.titleLayout.padding = [10, 5, 10, 5];
            this.titleLayout.verticalGravity = 16;
            
            titleText.textColor = Menu.theme.primaryTextColor;
            titleText.textSize = 18;
            titleText.gravity = Api.CENTER;
            
            titleParams.addRule(Api.CENTER_HORIZONTAL);
            titleText.layoutParams = titleParams;
            
            subtitleText.ellipsize = Api.TruncateAt.MARQUEE.value;
            subtitleText.marqueeRepeatLimit = -1;
            subtitleText.singleLine = true;
            subtitleText.selected = true;
            subtitleText.textColor = Menu.theme.primaryTextColor;
            subtitleText.textSize = 10;
            subtitleText.gravity = Api.CENTER;
            subtitleText.padding = [0, 0, 0, 5];
            
            this.scrollView.layoutParams = scrollParams;
            this.scrollView.backgroundColor = Menu.theme.layoutColor;
            this.layout.orientation = Api.VERTICAL;
            
            buttonView.padding = [10, 3, 10, 3];
            buttonView.verticalGravity = Api.CENTER;
            
            hideButtonParams.addRule(Api.ALIGN_PARENT_LEFT);
            hideButton.layoutParams = hideButtonParams;
            hideButton.backgroundColor = Api.TRANSPARENT;
            hideButton.textColor = Menu.theme.primaryTextColor;
            hideButton.onClickListener = () => {
                this.iconView.visibility = Api.VISIBLE;
                this.iconView.alpha = 0;
                this.expandedView.visibility = Api.GONE;
                toast(Menu.theme.iconHiddenText, 1);
            }

            hideButton.onLongClickListener = () => {
                this.destroy();
                toast(Menu.theme.killText, 1);
            }

            closeButtonParams.addRule(Api.ALIGN_PARENT_RIGHT);
            closeButton.layoutParams = closeButtonParams;
            closeButton.backgroundColor = 0;
            closeButton.textColor = Menu.theme.primaryTextColor;
            closeButton.onClickListener = () => {
                this.iconView.visibility = Api.VISIBLE;
                this.iconView.alpha = Menu.theme.iconAlpha;
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

            MainActivity.instance.onDestroy(() => this.destroy());
            MainActivity.instance.onPause(() => this.hide());
            MainActivity.instance.onResume(() => this.show());
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
                this.iconView = new Object(context);
                switch (type) {
                    case "Normal":
                        this.iconView.instance = Api.ImageView.$new(context);
                        this.iconView.instance.setScaleType(Api.ScaleType.FIT_XY.value);
                        this.iconView.onClickListener = () => {
                            this.iconView.visibility = Api.GONE;
                            this.expandedView.visibility = Api.VISIBLE;
                        }
                        this.iconView.instance.setImageBitmap(bitmap(value));
                        // ImageView uses alpha in range 0-255, unlike WebView (0.0 - 1.0)
                        Menu.theme.iconAlpha = Math.round(Menu.theme.iconAlpha * 255);
                        break;
                    case "Web":
                        this.iconView.instance = Api.WebView.$new(context);
                        this.iconView.instance.loadData(`<html><head></head><body style=\"margin: 0; padding: 0\"><img src=\"${value}\" width=\"${Menu.theme.iconSize}\" height=\"${Menu.theme.iconSize}\" ></body></html>`, "text/html", "utf-8");
                        this.iconView.backgroundColor = Api.TRANSPARENT;
                        this.iconView.instance.getSettings().setAppCacheEnabled(true);
                        break;
                    default:
                        throw Error("Unsupported icon type!");
                }
                this.iconView.layoutParams = Layout.LinearLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
                let applyDimension = Math.floor(dp(Menu.theme.iconSize));
                this.iconView.instance.getLayoutParams().height.value = applyDimension;
                this.iconView.instance.getLayoutParams().width.value = applyDimension;
                this.iconView.alpha = Menu.theme.iconAlpha;
                this.iconView.visibility = Api.VISIBLE;
                
                new OnTouch(this.rootFrame);
                new OnTouch(this.iconView);

                this.add(this.iconView, this.rootFrame);
            });
        }

        /** Sets menu settings */
        public settings(label: string, state: boolean): Layout {
            let settings = new TextView(label);
            let settingsView = Api.LinearLayout.$new(context);
            settingsView.orientation = Api.VERTICAL;
            settings.textColor = Menu.theme.primaryTextColor;
            settings.typeface = Api.Typeface.DEFAULT_BOLD.value;
            settings.textSize = 20;
            let settingsParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
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

        destroy() {
            MainActivity.instance.onPause(null);
            MainActivity.instance.onResume(null);
            MainActivity.instance.onDestroy(null);
            this.hide();
            this.rootFrame.destroy();
            this.layout.destroy();
        }

        /** Shows menu */
        public show() {
            Java.scheduleOnMainThread(() => {
                try {
                    app.windowManager.addView(this.rootFrame.instance, this.menuParams);
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
         * @param {Object} view to add
         * @param {?(Java.Wrapper | Object)} [layout] for add. If not provided general layout will be used
         */
        public add(view: Object, layout?: Java.Wrapper | Object) {
            Java.scheduleOnMainThread(() => {
                const l = layout ?? this.layout;
                (l instanceof Object ? l.instance : l).addView((view instanceof Object ? view.instance : view));
            })
        }

        /**
         * Removes view from layout
         *
         * @public
         * @param {Object} view to remove
         * @param {?(Java.Wrapper | Object)} [layout] for remove. If not provided general layout will be used
         */
        public remove(view: Object, layout?: Java.Wrapper | Object) {
            Java.scheduleOnMainThread(() => {
                const l = layout ?? this.layout;
                (l instanceof Object ? l.instance : l).removeView((view instanceof Object ? view.instance: view));
            })
        }

        button(text?: string, callback?: (this: Button) => void, longCallback?: (this: Button) => void): Button {
            const button = new Button(text);
            const params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
            params.setMargins(7, 5, 7, 5);
            button.layoutParams = params;
            button.allCaps = false;
            button.textColor = Menu.theme.secondaryTextColor;
            button.backgroundColor = Menu.theme.buttonColor;
            if (callback) button.onClickListener = () => callback.call(button);
            if (longCallback) button.onLongClickListener = () => longCallback.call(button);
    
            return button;
        }

        async dialog(title: string, message: string, positiveCallback?: (this: Dialog) => void, negativeCallback?: (this: Dialog) => void, view?: Java.Wrapper | Object): Promise<Dialog> {
            //We can create a dialog only with an activity instance, the context is not suitable.
            const instance = await MainActivity.instance.getActivityInstance();
            const dialog = new Dialog(instance, title, message);
            view ? (view instanceof Object ? dialog.view = view.instance : dialog.view = view) : null;
            if (positiveCallback) dialog.setPositiveButton(positiveCallback)
            if (negativeCallback) dialog.setNegativeButton(negativeCallback);
    
            return dialog;
        }

        radioGroup(label: string, buttons: string[], callback?: (this: RadioGroup, index: number) => void): RadioGroup {
            const radioGroup = new RadioGroup(label, Menu.theme);
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
            const seekbar = new SeekBar(label, Menu.instance.sharedPrefs.getInt(label));
            const layout = new Object(context);
            layout.instance = Api.LinearLayout.$new(context);
            layout.layoutParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
            layout.orientation = Api.VERTICAL;
            seekbar.padding = [25, 10, 35, 10];
            seekbar.max = max;
            min ? seekbar.min = min : seekbar.min = 0;
            if (callback) seekbar.onSeekBarChangeListener = callback;
    
            add(seekbar.label, layout);
            add(seekbar, layout);
    
            return layout;
        }

        spinner(items: string[], callback?: (this: Spinner, index: number) => void): Spinner {
            const spinner = new Spinner(items, Menu.theme);
            const savedIndex = Menu.instance.sharedPrefs.getInt(items.join());
            if (savedIndex != -1 && spinner.selection != savedIndex) Java.scheduleOnMainThread(() => spinner.selection = savedIndex);
            if (callback) spinner.onItemSelectedListener = callback;
            return spinner;
        }

        toggle(label: string, callback?: (this: Switch, state: boolean) => void): Switch {
            //switch keyword already used, so we borrow the name from lgl code
            const toggle = new Switch(label);
            const savedState = Menu.instance.sharedPrefs.getBool(label);
            toggle.textColor = Menu.theme.secondaryTextColor;
            toggle.padding = [10, 5, 10, 5];
            if (callback) toggle.onCheckedChangeListener = callback;
            if (savedState) Java.scheduleOnMainThread(() => toggle.checked = savedState);
    
            return toggle;
        }

        textView(label: string): TextView {
            const textView = new TextView(label);
            textView.textColor = Menu.theme.secondaryTextColor;
            textView.padding = [10, 5, 10, 5];
    
            return textView;
        }

        /** Creates category */
        public category(label: string): TextView {
            const textView = this.textView(label);
            textView.backgroundColor = Menu.theme.categoryColor;
            textView.gravity = Api.CENTER;
            textView.padding = [0, 5, 0, 5];
            textView.typeface = Api.Typeface.DEFAULT_BOLD.value;
            return textView;
        }

        public async inputNumber(title: string, max: number, positiveCallback?: (this: Dialog, result: number) => void, negativeCallback?: (this: Dialog) => void): Promise<void> {
            let view = Api.EditText.$new(context);
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

        /** Creates collapse */
        public collapse(label: string, state: boolean): [Layout, Layout] {
            let parentLayout = new Layout(Api.LinearLayout);
            let layout = new Layout(Api.LinearLayout);
            let textView = this.category(`▽ ${label} ▽`);
            let params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
            textView.backgroundColor = Menu.theme.collapseColor;
            params.setMargins(0, 5, 0, 0);
            parentLayout.layoutParams = params;
            parentLayout.verticalGravity = 16;
            parentLayout.orientation = Api.VERTICAL;

            layout.verticalGravity = 16;
            layout.padding = [0, 5, 0, 5];
            layout.orientation = Api.VERTICAL;
            layout.backgroundColor = Menu.theme.layoutColor;
            layout.visibility = Api.GONE;

            textView.padding = [0, 20, 0, 20];
            if (state) {
                layout.visibility = Api.VISIBLE;
                textView.text = `△ ${label} △`;
            }
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
            this.add(textView, parentLayout);
            this.add(layout, parentLayout);
            return [parentLayout, layout];
        }
    }
}
