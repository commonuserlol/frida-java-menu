namespace Menu {
    export class Menu {
        private collapsedView: Layout;
        private expandedView: Layout;
        private iconView: Object;
        private isAlive: boolean;
        private layout: Layout;
        private menuParams: Java.Wrapper;
        private rootContainer: Layout;
        private rootFrame: Layout;
        private scrollView: Layout;
        private settingsView: Layout;
        private static instance: Menu;
        private titleLayout: Layout;
        public context: Java.Wrapper;
        public sharedPrefs: Api.SharedPreferences;
        public theme: Theme;
        public windowManager: Java.Wrapper;

        constructor (title: string, subtitle: string, theme: Theme) {
            Menu.instance = this;
            this.context = Api.ActivityThread.currentApplication().getApplicationContext();
            this.theme = theme;
            this.isAlive = true;
            if (!checkOverlayPermission(this.context)) {
                toast(this.context, this.theme.noOverlayPermissionText, 1);
                requestOverlayPermission(this.context);
                throw Error("No permission provided! Aborting...");
            }
            this.sharedPrefs = new Api.SharedPreferences(this.context);
            this.windowManager = Java.retain(Java.cast(this.context.getSystemService(Api.WINDOW_SERVICE), Api.ViewManager));
            this.rootFrame = new Layout(this.context, Api.FrameLayout);
            this.rootContainer = new Layout(this.context, Api.RelativeLayout);
            this.menuParams = Api.WindowManager_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT, getApiLevel() >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value, 8, -3); 
            this.collapsedView = new Layout(this.context, Api.RelativeLayout);
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
            
            this.collapsedView.visibility = Api.VISIBLE;
            this.collapsedView.alpha = this.theme.iconAlpha;
            
            this.expandedView.visibility = Api.GONE;
            this.expandedView.visibility = this.theme.bgColor;
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
                this.collapsedView.visibility = Api.VISIBLE;
                this.collapsedView.alpha = 0;
                this.expandedView.visibility = Api.GONE;
                toast(this.context, this.theme.iconHiddenText, 1);
            }
            hideButton.onLongClickListener = () => {
                this.destroy();
                this.isAlive = false;
                toast(this.context, this.theme.killText, 1);
                MainActivity.instance.onPause = null;
                MainActivity.instance.onResume = null;
                MainActivity.instance.onDestroy = null;
            }

            closeButtonParams.addRule(Api.ALIGN_PARENT_RIGHT);
            closeButton.layoutParams = closeButtonParams;
            closeButton.backgroundColor = 0;
            closeButton.text = this.theme.closeText;
            closeButton.textColor = this.theme.primaryTextColor;
            closeButton.onClickListener = () => {
                this.collapsedView.visibility = Api.VISIBLE;
                this.collapsedView.alpha = this.theme.iconAlpha;
                this.expandedView.visibility = Api.GONE;
            }

            new Api.OnTouch(this.windowManager, this.collapsedView.instance, this.expandedView.instance, this.rootFrame.instance, this.menuParams).setUser(this.rootFrame.instance);
            
            this.add(this.collapsedView, this.rootContainer);
            this.add(this.expandedView, this.rootContainer);
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
                this.destroy();
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
                            this.collapsedView.visibility = Api.GONE;
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
                new Api.OnTouch(this.windowManager, this.collapsedView.instance, this.expandedView.instance, this.rootFrame.instance, this.menuParams).setUser(this.iconView.instance);
                
                this.add(this.iconView, this.collapsedView);
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
            this.settingsView = Api.LinearLayout.$new(this.context);
            this.settingsView.orientation = Api.VERTICAL;
            settings.textColor = this.theme.primaryTextColor;
            settings.typeface = Api.Typeface.DEFAULT_BOLD.value;
            settings.textSize = 20;
            let settingsParams = Api.RelativeLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            settingsParams.addRule(Api.ALIGN_PARENT_RIGHT);
            settings.layoutParams = settingsParams;
            if (state) {
                this.remove(this.layout, this.scrollView);
                this.add(this.settingsView, this.scrollView);
            }
            settings.onClickListener = () => {
                state = !state;
                if (state) {
                    this.remove(this.layout, this.scrollView);
                    this.add(this.settingsView, this.scrollView);
                }
                else {
                    this.remove(this.settingsView, this.scrollView);
                    this.add(this.layout, this.scrollView);
                }
            }
            this.add(settings, this.titleLayout);
            return this.settingsView;
        }

        /**
         * Destroys menu
         *
         * @public
         */
        public destroy(): void {
            Java.scheduleOnMainThread(() => {
                try {
                    this.remove(this.rootContainer, this.rootFrame);
                    this.rootFrame.visibility = Api.GONE;
                    this.remove(this.rootFrame, this.windowManager);
                }
                catch (e) {
                    console.warn("Menu already destroyed, ignoring `destroy` call");
                }
            });
        }

        /**
         * Shows menu
         *
         * @public
         */
        public show(): void {
            Java.scheduleOnMainThread(() => {
                if (!this.isAlive) return;
                try {
                    this.windowManager.addView(this.rootFrame, this.menuParams);
                    this.add(this.rootContainer, this.rootFrame);
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

        /**
         * Creates category
         *
         * @public
         * @param {string} text
         * @returns {TextView}
         */
        public category(text: string): TextView {
            const label = textView(text);
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
            await dialog(title, "", function () {
                let result = parseFloat(Java.cast(view, Api.TextView).getText().toString());
                !Number.isNaN(result) ? positiveCallback?.call(this, result <= max ? result : max) : positiveCallback?.call(this, NaN);
            }, function () {
                negativeCallback?.call(this);
            }, view).then((d) => d.show());  
        }

        public async inputText(title: string, hint?: string, positiveCallback?: (this: Dialog, result: string) => void, negativeCallback?: (this: Dialog) => void): Promise<void> {
            let view = Api.EditText.$new(this.context);
            if (hint) view.setHint(wrap(hint));
            await dialog(title, "", function () {
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
        /** Gets instance of menu */
        public static getInstance(): Menu {
            return this.instance;
        }
    }
}
