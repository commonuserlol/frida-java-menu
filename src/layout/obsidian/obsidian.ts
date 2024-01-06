namespace Menu {
    interface ObsidianColorConfig extends ColorConfig {
        tabFocusedBg: string,
        tabUnfocusedBg: string,
        hideFg: string,
        closeFg: string
    }

    interface ObsidianMenuConfig extends MenuConfig {
        cornerRadius: number
    }

    export interface ObsidianConfig extends GenericConfig {
        color: ObsidianColorConfig,
        menu: ObsidianMenuConfig
    }
    /** Own layout configuration */
    export declare const ObsidianLayoutConfig: ObsidianConfig;
    getter(Menu, "ObsidianLayoutConfig", () => {
        return {
            color: {
                primaryText: "#78281F",
                secondaryText: "#5B2C6F",
                buttonBg: "#1D1D1D",
                layoutBg: "#111111",
                collapseBg: "#3B3B3B",
                categoryBg: "#296368",
                tabUnfocusedBg: "#3E3E3E",
                tabFocusedBg: "#454545",
                hideFg: "#1E75A4",
                closeFg: "#970000",
                menu: "#000000"
            },

            menu: {
                width: 300,
                height: 200,
                x: 100,
                y: 100,
                cornerRadius: 45
            },

            icon: {
                size: 35,
                alpha: 0.6
            },

            strings: {
                noOverlayPermission: "Overlay permission is needed to show the menu",
                hide: "<b>_</b>",
                close: "✖",
                hideCallback: "Icon hidden",
                killCallback: "Menu killed"
            }
        };
    }, lazy);

    /** Obsidian layout */
    export class ObsidianLayout extends GenericLayout {
        declare hide: TextView;
        declare close: TextView;
        buttonProxyLayout: Layout;

        constructor(cfg?: GenericConfig) {
            super(cfg ?? ObsidianLayoutConfig);
            const titleParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT); // For `this.title`
            titleParams.addRule(Api.RelativeLayout.CENTER_IN_PARENT.value);

            this.title = new TextView();
            this.title.textColor = config.color.primaryText;
            this.title.textSize = 18;
            this.title.gravity = Api.CENTER;
            this.title.layoutParams = titleParams;

            this.subtitle = new TextView();
            this.subtitle.ellipsize = Api.TruncateAt.MARQUEE.value;
            this.subtitle.marqueeRepeatLimit = -1;
            this.subtitle.singleLine = true;
            this.subtitle.selected = true;
            this.subtitle.textColor = config.color.primaryText;
            this.subtitle.textSize = 10;
            this.subtitle.gravity = Api.CENTER;
            this.subtitle.padding = [0, 0, 0, 5];
        }

        /** @internal */
        roundedDrawable(): Java.Wrapper {
            const gradientDrawable = Api.GradientDrawable.$new();
            gradientDrawable.setCornerRadius((config as ObsidianConfig).menu.cornerRadius);

            return gradientDrawable;
        }

        initializeParams(): void {
            super.initializeParams();
            this.params.gravity.value = 51;
            this.params.x.value = config.menu.x;
            this.params.y.value = config.menu.y;
        }

        initializeLayout(): void {
            const gradientDrawable = this.roundedDrawable();
            gradientDrawable.setColor(parseColor(config.color.menu));

            this.me = new Layout(Api.LinearLayout);
            this.me.visibility = Api.GONE;
            this.me.background = gradientDrawable;
            this.me.orientation = Api.VERTICAL;
            this.me.layoutParams = Layout.LinearLayoutParams(Math.floor(dp(config.menu.width)), Api.WRAP_CONTENT);
        }

        initializeIcon(): void {}

        initializeProxy(): void {
            super.initializeProxy();

            // without roundind proxy it only top corners will be rounded
            const gradientDrawable = this.roundedDrawable();
            gradientDrawable.setColor(parseColor(config.color.layoutBg));

            this.proxy.layoutParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Math.floor(dp(config.menu.height)));
            this.proxy.background = gradientDrawable;
        }

        initializeMainLayout(): void {
            this.layout = new Layout(Api.LinearLayout);
            this.layout.orientation = Api.VERTICAL;
        }

        initializeButtons(): void {
            const buttonProxyLayoutParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            buttonProxyLayoutParams.addRule(Api.ALIGN_PARENT_RIGHT);

            this.buttonProxyLayout = new Layout(Api.LinearLayout);
            this.buttonProxyLayout.orientation = Api.HORIZONTAL;
            this.buttonProxyLayout.layoutParams = buttonProxyLayoutParams;

            this.buttonLayout = new Layout(Api.RelativeLayout);
            this.buttonLayout.padding = [10, 3, 10, 3];
            this.buttonLayout.verticalGravity = Api.CENTER;

            this.hide = new TextView(config.strings.hide);
            this.hide.padding = [15, 3, 15, 3];
            this.hide.backgroundColor = Api.TRANSPARENT;
            this.hide.textColor = (config as ObsidianConfig).color.hideFg;
            this.hide.onClickListener = () => {
                Menu.instance.$icon.visibility = Api.VISIBLE;
                Menu.instance.$icon.alpha = 0;
                this.me.visibility = Api.GONE;
                toast(config.strings.hideCallback, 1);
            }
            this.hide.onLongClickListener = () => {
                instance.destroy();
                toast(config.strings.killCallback, 1);
            }

            this.close = new TextView(config.strings.close);
            this.close.padding = [15, 3, 15, 3];
            this.close.backgroundColor = Api.TRANSPARENT;
            this.close.textColor = (config as ObsidianConfig).color.closeFg;
            this.close.onClickListener = () => {
                Menu.instance.$icon.visibility = Api.VISIBLE;
                Menu.instance.$icon.alpha = config.icon.alpha;
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
            add(this.buttonProxyLayout, this.buttonLayout);
            add(this.buttonLayout, this.me);
            add(this.title, this.buttonLayout);
            add(this.subtitle, this.me);
            add(this.layout, this.proxy);
            add(this.proxy, this.me);
            add(this.hide, this.buttonProxyLayout);
            add(this.close, this.buttonProxyLayout);
        }

        handleRemove(remove: ComposerHandler): void {
            remove(this.buttonProxyLayout, this.buttonLayout);
            remove(this.buttonLayout, this.me);
            remove(this.close, this.buttonProxyLayout);
            remove(this.hide, this.buttonProxyLayout);
            remove(this.proxy, this.me);
            remove(this.layout, this.proxy);
            remove(this.subtitle, this.me);
            remove(this.title, this.buttonLayout);
        }

        button(text: string, callback?: ThisCallback<Button>, longCallback?: ThisCallback<Button>): Button {
            const params = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
            params.setMargins(7, 5, 7, 5);

            const button = Menu.button(text, callback, longCallback);
            button.layoutParams = params;
            button.allCaps = false;
            button.textColor = config.color.secondaryText;
            button.backgroundColor = config.color.buttonBg;

            return button;
        }

        async dialog(title: string, message: string, positiveCallback?: DialogCallback, negativeCallback?: DialogCallback, view?: Java.Wrapper): Promise<Dialog> {
            const dialog = await Menu.dialog(title, message, positiveCallback, negativeCallback, view);;
            return dialog;
        }

        radioGroup(label: string, buttons: string[], callback?: ThisWithIndexCallback<Button>): RadioGroup {
            const radioGroupLabel = this.textView(format(label, ""));

            const radioGroupLabelParams = Layout.LinearLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);

            const instances = makeButtonInstances(buttons, function (index: number) {
                radioGroupLabel.text = format(label, this.text);
                callback?.call(this, index);
            }).map(e => {
                e.textColor = config.color.secondaryText;
                return e;
            });

            const radioGroup = Menu.radioGroup(instances);
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
            seekbar.padding = [25, 10, 35, 10];

            const seekbarLabel = this.textView(format(label, seekbar.progress));

            const layout = new Layout(Api.LinearLayout);
            layout.layoutParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Api.MATCH_PARENT);
            layout.orientation = Api.VERTICAL;

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
    }
}