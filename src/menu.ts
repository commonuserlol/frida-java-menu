namespace Menu {
    /** `Composer` class instance */
    export declare let instance: Composer;
    /** Config instance for layout */
    export declare let config: Menu.GenericConfig;
    /** Shared Preferences storage. Feel free to store own values */
    export declare const sharedPreferences: SharedPreferences;

    getter(Menu, "sharedPreferences", () => new SharedPreferences(), lazy);
    
    /** Main class for menu */
    export class Composer<T extends Menu.GenericLayout = Menu.GenericLayout> {
        /** @internal */
        rootFrame: Layout;
        /** Icon holder */
        icon: Icon;
        /** Layout layout */
        layout: T;

        constructor (title: string, subtitle: string, layout: T) {
            Menu.instance = this;

            if (!overlay.check()) {
                overlay.ask();
                setTimeout(async () => (await activityInstance).finish(), 3000);
            }

            this.rootFrame = new Layout(Api.FrameLayout);
            this.layout = layout;
            this.layout.title.text = title;
            this.layout.subtitle.text = subtitle;
            
            add(this.layout.me, this.rootFrame);
            this.layout.handleAdd(add);

            onDestroy(() => this.destroy());
            onPause(() => this.hide());
            onResume(() => this.show());
        }

        /**
         * Sets icon for menu
         *
         * @param {string} value can be base64-encoded image or link (only for Web type)
         * @param {("Normal" | "Web")} [type="Normal"] Normal accepts only base64-encoded image. Web accepts links to images/gifs, etc
         */
        iconImage(value: string, type: "Normal" | "Web" = "Normal") {
            Java.scheduleOnMainThread(() => {
                this.icon = new Icon(type, value);

                this.icon.onClickListener = () => {
                    this.icon.visibility = Api.GONE;
                    this.layout.me.visibility = Api.VISIBLE;
                }
                this.icon.visibility = Api.VISIBLE;

                this.layout.initializeIcon();
                
                new OnTouch(this.rootFrame);
                new OnTouch(this.icon);

                add(this.icon, this.rootFrame);
            });
        }

        /** Sets menu settings */
        settings(label: string, state: boolean = false): Layout {
            const settings = new Settings(label, state);
            settings.orientation = Api.VERTICAL;
            add(settings.settings, this.layout.titleLayout);
            return settings;
        }

        /** Hides menu */
        hide() {
            Java.scheduleOnMainThread(() => {
                try {
                    this.rootFrame.visibility = Api.GONE;
                    remove(this.rootFrame, app.windowManager);
                }
                catch (e) {
                    console.warn("Menu already destroyed, ignoring `destroy` call");
                }
            });
        }

        /** Disposes instance of `Composer` */
        destroy() {
            onPause();
            onResume();
            onDestroy();
            this.hide();
            remove(this.layout.me, this.rootFrame);
            this.layout.handleRemove(remove);
            this.layout.destroy();
            this.rootFrame.destroy();
        }

        /** Shows menu */
        show() {
            Java.scheduleOnMainThread(() => {
                try {
                    app.windowManager.addView(this.rootFrame.instance, this.layout.params);
                    this.rootFrame.visibility = Api.VISIBLE;
                }
                catch (e) {
                    console.warn("Menu already showed, ignoring `show` call");
                }
            });
        }
    }

    /** Backwards compatible name with the new one.
     * 
     * Please do NOT use it for new projects
     * 
     * It WILL be removed after a few versions */
    export class JavaMenu<T extends Menu.GenericLayout = Menu.GenericLayout> extends Composer<T> {}
}
