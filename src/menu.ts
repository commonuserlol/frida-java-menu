namespace Menu {
    /** `Composer` class instance */
    export declare let instance: Composer;
    /** Config instance for template */
    export declare let config: Menu.GenericConfig;
    /** Shared Preferences storage. Feel free to store own values */
    export declare const sharedPreferences: SharedPreferences;

    getter(Menu, "sharedPreferences", () => new SharedPreferences(), lazy);
    
    /** Main class for menu */
    export class Composer<T extends Menu.GenericLayout = Menu.GenericLayout> {
        /** @internal */
        rootFrame: Layout;
        /** Layout template */
        template: T;

        constructor (title: string, subtitle: string, template: T) {
            Menu.instance = this;

            if (!overlay.check()) {
                overlay.ask();
                setTimeout(async () => (await activityInstance).finish(), 3000);
            }

            this.rootFrame = new Layout(Api.FrameLayout);
            this.template = template;
            this.template.title.text = title;
            this.template.subtitle.text = subtitle;
            
            add(this.template.me, this.rootFrame);
            this.template.handleAdd(add);

            onDestroy(() => this.destroy());
            onPause(() => this.hide());
            onResume(() => this.show());
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
                
                new OnTouch(this.rootFrame);
                new OnTouch(this.template.icon);

                add(this.template.icon, this.rootFrame);
            });
        }

        /** Sets menu settings */
        public settings(label: string, state: boolean = false): Layout {
            const settings = new Settings(label, state);
            settings.orientation = Api.VERTICAL;
            add(settings.settings, this.template.titleLayout);
            return settings;
        }

        /** Hides menu */
        public hide() {
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
            remove(this.template.me, this.rootFrame);
            this.template.handleRemove(remove);
            this.template.destroy();
            this.rootFrame.destroy();
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
    }

    /** Backwards compatible name with the new one.
     * 
     * Please do NOT use it for new projects
     * 
     * It WILL be removed after a few versions */
    export class JavaMenu<T extends Menu.GenericLayout = Menu.GenericLayout> extends Composer<T> {}
}
