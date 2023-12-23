namespace Menu {
    /** First layout - to add to the layout; Second - for your widgets */
    export declare type CollapseReturn = [Layout, Layout];
    /** LGL Layout configuration */
    export declare const LGLConfig: GenericConfig;
    getter(Menu, "LGLConfig", () => {
        return {
            color: {
                primaryText: "#82CAFD",
                secondaryText: "#FFFFFF",
                buttonBg: "#1C262D",
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
    export class LGLLayout extends GenericLayout {
        constructor(cfg?: GenericConfig) {
            super(cfg ?? LGLConfig);
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
            super.initializeParams();
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

        initializeIcon(): void {}

        initializeProxy(): void {
            super.initializeProxy();
            const proxyParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Math.floor(dp(config.menu.height)));
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
                Menu.instance.icon.visibility = Api.VISIBLE;
                Menu.instance.icon.alpha = 0;
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
                Menu.instance.icon.visibility = Api.VISIBLE;
                Menu.instance.icon.alpha = config.icon.alpha;
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

        handleAdd(add: ComposerHandler): void {
            add(this.title, this.titleLayout);
            add(this.titleLayout, this.me);
            add(this.subtitle, this.me);
            add(this.layout, this.proxy);
            add(this.proxy, this.me);
            add(this.hide, this.buttonLayout);
            add(this.close, this.buttonLayout);
            add(this.buttonLayout, this.me);
        }

        handleRemove(remove: ComposerHandler): void {
            remove(this.buttonLayout, this.me);
            remove(this.close, this.buttonLayout);
            remove(this.hide, this.buttonLayout);
            remove(this.proxy, this.me);
            remove(this.layout, this.proxy);
            remove(this.subtitle, this.me);
            remove(this.titleLayout, this.me);
            remove(this.title, this.titleLayout);
        }

        button(text: string, callback?: ThisCallback<Button>, longCallback?: ThisCallback<Button>): Button {
            const button = Menu.button(text, callback, longCallback);
            const params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
            params.setMargins(7, 5, 7, 5);
            button.layoutParams = params;
            button.allCaps = false;
            button.textColor = config.color.secondaryText;
            button.backgroundColor = config.color.buttonBg;

            return button;
        }

        async dialog(title: string, message: string, positiveCallback?: DialogCallback, negativeCallback?: DialogCallback, view?: Java.Wrapper): Promise<Dialog> {
            const dialog = await Menu.dialog(title, message, positiveCallback, negativeCallback, view);
            // I have no idea should I show dialog
            // But let user care about this
            // Reference: https://github.com/LGLTeam/Android-Mod-Menu/blob/2e6095c7cb85458fff07f413d95d98a22e195cfa/app/src/main/java/com/android/support/Menu.java#L812
            return dialog;
        }

        radioGroup(label: string, buttons: string[], callback?: ThisWithIndexCallback<Button>): RadioGroup {
            const instances = makeButtonInstances(buttons, function (index: number) {
                radioGroupLabel.text = format(label, this.text);
                callback?.call(this, index);
            }).map(e => {
                e.textColor = config.color.secondaryText;
                return e;
            });
            const radioGroup = Menu.radioGroup(instances);
            const radioGroupLabel = this.textView(format(label, ""));
            const radioGroupLabelParams = Layout.LinearLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            radioGroup.padding = [10, 5, 10, 5];
            radioGroup.orientation = Api.VERTICAL;
            radioGroup.instance.addView(Java.cast(radioGroupLabel.instance, Api.View), buttons.length, radioGroupLabelParams);

            return radioGroup;
        }

        seekbar(label: string, max: number, min?: number, callback?: SeekBarCallback): View {
            const seekbar = Menu.seekbar(label, max, min, (progress: number) => {
                seekbarLabel.text = format(label, progress);
                callback?.call(seekbar, progress);
            });
            const seekbarLabel = this.textView(format(label, seekbar.progress));
            const layout = new Layout(Api.LinearLayout);
            layout.layoutParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
            layout.orientation = Api.VERTICAL;
            seekbar.padding = [25, 10, 35, 10];

            add(seekbarLabel, layout);
            add(seekbar, layout);

            return layout;
        }

        spinner(items: string[], callback?: ThisWithIndexCallback<Spinner>): Spinner {
            const spinner = Menu.spinner(items, callback);
            spinner.background.setColorFilter(1, Api.Mode.SRC_ATOP.value);

            return spinner;
        }

        toggle(label: string, callback?: SwitchCallback): Switch {
            const toggle = Menu.toggle(label, callback);
            toggle.textColor = config.color.secondaryText;
            toggle.padding = [10, 5, 10, 5];

            return toggle;
        }

        textView(label: string): TextView {
            const textView = Menu.textView(label);
            textView.textColor = config.color.secondaryText;
            textView.padding = [10, 5, 10, 5];

            return textView;
        }

        category(label: string): TextView {
            const textView = Menu.textView(label);
            textView.backgroundColor = config.color.categoryBg;
            textView.gravity = Api.CENTER;
            textView.padding = [0, 5, 0, 5];
            textView.typeface = Api.Typeface.DEFAULT_BOLD.value;

            return textView;
        }

        collapse(label: string, state: boolean): CollapseReturn {
            const parentLayout = new Layout(Api.LinearLayout);
            const layout = new Layout(Api.LinearLayout);
            const textView = this.category(`▽ ${label} ▽`);
            const params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
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
            textView.onClickListener = stateHolder(state, (s: boolean) => {
                if (s) {
                    layout.visibility = Api.VISIBLE;
                    textView.text = `△ ${label} △`;
                }
                else {
                    layout.visibility = Api.GONE;
                    textView.text = `▽ ${label} ▽`;
                }
            });
            add(textView, parentLayout);
            add(layout, parentLayout);
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
            Menu.instance.icon.destroy();
            this.me.destroy();
        }
    }
}