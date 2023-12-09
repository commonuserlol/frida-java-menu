namespace Menu {
    export namespace Template {
        /** LGL Template configuration */
        export declare const LGLConfig: GenericConfig;
        getter(Menu.Template, "LGLConfig", () => {
            return {
                color: {
                    primaryText: "#82CAFD",
                    secondaryText: "#FFFFFF",
                    button: {
                        fg: "#FFFFFF", // TODO: Should i sync it with `secondaryText` ?
                        bg: "#1C262D",
                        on: "#1B5E20",
                        off: "#7F0000"
                    },
                    layoutBg: "#DD141C22",
                    collapseBg: "#222D38",
                    categoryBg: "#2F3D4C",
                    menu: "#EE1C2A35"
                },

                menu: {
                    width: 290,
                    height: 210,
                    x: 50,
                    y: 100,
                },

                icon: {
                    size: 45,
                    alpha: 0.7
                },

                strings: {
                    noOverlayPermission: "Overlay permission required to show menu",
                    hide: "HIDE/KILL (Hold)",
                    close: "MINIMIZE",
                    hideCallback: "Icon hidden. Remember the hidden icon position",
                    killCallback: "Menu killed"
                }
            };
        }, lazy);

        /** LGL Mod Menu template */
        export class LGLTemplate extends GenericTemplate {
            constructor() {
                super();
                config = LGLConfig;
                this.titleLayout = new Layout(Api.RelativeLayout);
                this.title = new TextView();
                this.subtitle = new TextView();

                // Configure title & subtitle
                const titleParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT); // For `this.title`
                titleParams.addRule(Api.CENTER_HORIZONTAL);

                this.titleLayout.padding = [10, 5, 10, 5];
                this.titleLayout.verticalGravity = 16;
                
                this.title.textColor = config.color.primaryText;
                this.title.textSize = 18;
                this.title.gravity = Api.CENTER;
                this.title.layoutParams = titleParams;
                
                this.subtitle.ellipsize = Api.TruncateAt.MARQUEE.value;
                this.subtitle.marqueeRepeatLimit = -1;
                this.subtitle.singleLine = true;
                this.subtitle.selected = true;
                this.subtitle.textColor = config.color.primaryText;
                this.subtitle.textSize = 10;
                this.subtitle.gravity = Api.CENTER;
                this.subtitle.padding = [0, 0, 0, 5];

                this.ensureInitialized();
            }

            initializeParams(): void {
                this.params = Api.WindowManager_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT, apiLevel >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value, 8, -3);
                this.params.gravity.value = 51;
                this.params.x.value = config.menu.x;
                this.params.y.value = config.menu.y;
            }

            initializeLayout(): void {
                this.me = new Layout(Api.LinearLayout);
                this.me.visibility = Api.GONE;
                this.me.backgroundColor = config.color.menu;
                this.me.orientation = Api.VERTICAL;
                this.me.layoutParams = Layout.LinearLayoutParams(Math.floor(dp(config.menu.width)), Api.WRAP_CONTENT);
            }

            initializeIcon(value: string, type?: "Normal" | "Web"): void {
                this.icon = new Icon(type, value);

                this.icon.onClickListener = () => {
                    this.icon.visibility = Api.GONE;
                    this.me.visibility = Api.VISIBLE;
                }

                this.icon.visibility = Api.VISIBLE;
            }

            initializeProxy(): void {
                const proxyParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Math.floor(dp(config.menu.height)));
                this.proxy = new Layout(Api.ScrollView);
                this.proxy.layoutParams = proxyParams;
                this.proxy.backgroundColor = config.color.layoutBg;
            }

            initializeMainLayout(): void {
                this.layout = new Layout(Api.LinearLayout);
                this.layout.orientation = Api.VERTICAL;
            }

            initializeButtons(): void {
                const hideButtonParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
                const closeButtonParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
                this.buttonLayout = new Layout(Api.RelativeLayout);
                this.hide = new Button(config.strings.hide);
                this.close = new Button(config.strings.close);
                this.buttonLayout.padding = [10, 3, 10, 3];
                this.buttonLayout.verticalGravity = Api.CENTER;
                
                hideButtonParams.addRule(Api.ALIGN_PARENT_LEFT);
                this.hide.layoutParams = hideButtonParams;
                this.hide.backgroundColor = Api.TRANSPARENT;
                this.hide.textColor = config.color.primaryText;
                this.hide.onClickListener = () => {
                    this.icon.visibility = Api.VISIBLE;
                    this.icon.alpha = 0;
                    this.me.visibility = Api.GONE;
                    toast(config.strings.hideCallback, 1);
                }

                this.hide.onLongClickListener = () => {
                    instance.destroy();
                    toast(config.strings.killCallback, 1);
                }

                closeButtonParams.addRule(Api.ALIGN_PARENT_RIGHT);
                this.close.layoutParams = closeButtonParams;
                this.close.backgroundColor = 0;
                this.close.textColor = config.color.primaryText;
                this.close.onClickListener = () => {
                    this.icon.visibility = Api.VISIBLE;
                    this.icon.alpha = config.icon.alpha;
                    this.me.visibility = Api.GONE;
                }
            }

            ensureInitialized(): void {
                this.initializeParams();
                this.initializeLayout();
                this.initializeProxy();
                this.initializeMainLayout();
                this.initializeButtons();
            }

            handleAdd(add: (view: View, layout?: Java.Wrapper | View) => void): void {
                add(this.title, this.titleLayout);
                add(this.titleLayout, this.me);
                add(this.subtitle, this.me);
                add(this.layout, this.proxy);
                add(this.proxy, this.me);
                add(this.hide, this.buttonLayout);
                add(this.close, this.buttonLayout);
                add(this.buttonLayout, this.me);
            }

            handleRemove(remove: (view: View, layout?: Java.Wrapper | View) => void): void {
                remove(this.buttonLayout, this.me);
                remove(this.close, this.buttonLayout);
                remove(this.hide, this.buttonLayout);
                remove(this.proxy, this.me);
                remove(this.layout, this.proxy);
                remove(this.subtitle, this.me);
                remove(this.titleLayout, this.me);
                remove(this.title, this.titleLayout);
            }

            button(text?: string, callback?: ThisCallback<Button>, longCallback?: ThisCallback<Button>): Button {
                const button = super.button(text, callback, longCallback);
                const params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
                params.setMargins(7, 5, 7, 5);
                button.layoutParams = params;
                button.allCaps = false;
                button.textColor = config.color.secondaryText;
                button.backgroundColor = config.color.button.bg;

                return button;
            }

            radioGroup(label: string, buttons: string[], callback?: ThisWithIndexCallback<RadioGroup>): RadioGroup {
                const radioGroup = super.radioGroup(label, buttons, callback);
                radioGroup.padding = [10, 5, 10, 5];
                radioGroup.orientation = Api.VERTICAL;

                return radioGroup;
            }

            seekbar(label: string, max: number, min?: number, callback?: SeekBarCallback): View {
                const seekbar = super.seekbar(label, max, min, callback);
                const layout = new View();
                layout.instance = Api.LinearLayout.$new(app.context);
                layout.layoutParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
                layout.orientation = Api.VERTICAL;
                seekbar.padding = [25, 10, 35, 10];

                Menu.instance.add((seekbar as SeekBar).label, layout);
                Menu.instance.add(seekbar, layout);

                return layout;
            }

            toggle(label: string, callback?: SwitchCallback): Switch {
                const toggle = super.toggle(label, callback);
                toggle.textColor = config.color.secondaryText;
                toggle.padding = [10, 5, 10, 5];

                return toggle;
            }

            textView(label: string): TextView {
                const textView = super.textView(label);
                textView.textColor = config.color.secondaryText;
                textView.padding = [10, 5, 10, 5];

                return textView;
            }

            category(label: string): TextView {
                const textView = super.textView(label);
                textView.backgroundColor = config.color.categoryBg;
                textView.gravity = Api.CENTER;
                textView.padding = [0, 5, 0, 5];
                textView.typeface = Api.Typeface.DEFAULT_BOLD.value;

                return textView;
            }

            collapse(label: string, state: boolean): [Layout, Layout] {
                let parentLayout = new Layout(Api.LinearLayout);
                let layout = new Layout(Api.LinearLayout);
                let textView = this.category(`▽ ${label} ▽`);
                let params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
                textView.backgroundColor = config.color.collapseBg;
                params.setMargins(0, 5, 0, 0);
                parentLayout.layoutParams = params;
                parentLayout.verticalGravity = 16;
                parentLayout.orientation = Api.VERTICAL;

                layout.verticalGravity = 16;
                layout.padding = [0, 5, 0, 5];
                layout.orientation = Api.VERTICAL;
                layout.backgroundColor = config.color.layoutBg;
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
                Menu.instance.add(textView, parentLayout);
                Menu.instance.add(layout, parentLayout);
                return [parentLayout, layout];
            }

            destroy(): void {
                this.buttonLayout.destroy();
                this.close.destroy();
                this.hide.destroy();
                this.proxy.destroy();
                this.layout.destroy();
                this.subtitle.destroy();
                this.titleLayout.destroy();
                this.title.destroy();
                this.icon.destroy();
                this.me.destroy();
            }
        }
    }
}