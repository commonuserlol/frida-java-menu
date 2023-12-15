namespace Menu {
    /** `Composer` class instance */
    export declare let instance: Composer;
    /** Config instance for template */
    export declare let config: Menu.GenericConfig;
    /** Shared Preferences storage. Feel free to store own values */
    export declare const sharedPreferences: SharedPreferences;

    getter(Menu, "sharedPreferences", () => new SharedPreferences(), lazy);
    
    /** Main class for menu */
    export class Composer<T extends Menu.GenericTemplate = Menu.GenericTemplate> {
        /** @internal */
        rootFrame: Layout;
        /** Layout template */
        template: T;

        constructor (title: string, subtitle: string, template: T) {
            Menu.instance = this;

            if (!overlay.check()) {
                overlay.ask();
                setTimeout(() => MainActivity.getActivityInstance().then((instance) => instance.finish()), 3000);
            }

            this.rootFrame = new Layout(Api.FrameLayout);
            this.template = template;
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
                
                new OnTouch(this.rootFrame);
                new OnTouch(this.template.icon);

                this.add(this.template.icon, this.rootFrame);
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
            this.remove(this.template.me, this.rootFrame);
            this.template.handleRemove(this.remove);
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
    }

    /** Backwards compatible name with the new one.
     * 
     * Please do NOT use it for new projects
     * 
     * It WILL be removed after a few versions */
    export class JavaMenu<T extends Menu.GenericTemplate = Menu.GenericTemplate> extends Composer<T> {}
}
