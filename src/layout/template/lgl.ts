namespace Menu {
    export namespace Template {
        export declare const LGLConfig: GenericConfig;
        getter(Menu.Template, "LGLConfig", () => {
            return {
                primaryText: "#82CAFD",
                secondaryText: "#FFFFFF",
                buttonBg: "#1C262D",
                layoutBg: "#DD141C22",
                collapseBg: "#222D38",
                categoryBg: "#2F3D4C",

                width: 290,
                height: 210,
                x: 50,
                y: 100,

                size: 45,
                alpha: 0.7
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
                
                this.title.textColor = config.primaryTextColor;
                this.title.textSize = 18;
                this.title.gravity = Api.CENTER;
                this.title.layoutParams = titleParams;
                
                this.subtitle.ellipsize = Api.TruncateAt.MARQUEE.value;
                this.subtitle.marqueeRepeatLimit = -1;
                this.subtitle.singleLine = true;
                this.subtitle.selected = true;
                this.subtitle.textColor = config.primaryTextColor;
                this.subtitle.textSize = 10;
                this.subtitle.gravity = Api.CENTER;
                this.subtitle.padding = [0, 0, 0, 5];

                this.ensureInitialized();
            }

            initializeParams(): void {
                this.params = Api.WindowManager_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT, apiLevel >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value, 8, -3);
                this.params.gravity.value = 51;
                this.params.x.value = config.menuXPosition;
                this.params.y.value = config.menuYPosition;
            }

            initializeLayout(): void {
                this.me = new Layout(Api.LinearLayout);
                this.me.visibility = Api.GONE;
                this.me.backgroundColor = config.bgColor;
                this.me.orientation = Api.VERTICAL;
                this.me.layoutParams = Layout.LinearLayoutParams(Math.floor(dp(config.menuWidth)), Api.WRAP_CONTENT);
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
                const proxyParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Math.floor(dp(config.menuHeight)));
                this.proxy = new Layout(Api.ScrollView);
                this.proxy.layoutParams = proxyParams;
                this.proxy.backgroundColor = config.layoutColor;
            }

            initializeMainLayout(): void {
                this.layout = new Layout(Api.LinearLayout);
                this.layout.orientation = Api.VERTICAL;
            }

            initializeButtons(): void {
                const hideButtonParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
                const closeButtonParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
                this.buttonLayout = new Layout(Api.RelativeLayout);
                this.hide = new Button(config.hide);
                this.close = new Button(config.close);
                this.buttonLayout.padding = [10, 3, 10, 3];
                this.buttonLayout.verticalGravity = Api.CENTER;
                
                hideButtonParams.addRule(Api.ALIGN_PARENT_LEFT);
                this.hide.layoutParams = hideButtonParams;
                this.hide.backgroundColor = Api.TRANSPARENT;
                this.hide.textColor = config.primaryTextColor;
                this.hide.onClickListener = () => {
                    this.icon.visibility = Api.VISIBLE;
                    this.icon.alpha = 0;
                    this.me.visibility = Api.GONE;
                    toast(config.hideCallback, 1);
                }

                this.hide.onLongClickListener = () => {
                    instance.destroy();
                    toast(config.killCallback, 1);
                }

                closeButtonParams.addRule(Api.ALIGN_PARENT_RIGHT);
                this.close.layoutParams = closeButtonParams;
                this.close.backgroundColor = 0;
                this.close.textColor = config.primaryTextColor;
                this.close.onClickListener = () => {
                    this.icon.visibility = Api.VISIBLE;
                    this.icon.alpha = config.iconAlpha;
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