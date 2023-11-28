namespace Menu {
    export namespace Template {
        export class LGLTemplate extends GenericTemplate {
            constructor() {
                super();
                this.params = Api.WindowManager_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT, apiLevel >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value, 8, -3);
                this.me = new Layout(Api.LinearLayout);
                this.layout = new Layout(Api.LinearLayout);
                this.titleLayout = new Layout(Api.RelativeLayout);
                this.proxy = new Layout(Api.ScrollView);
                this.title = new TextView();
                this.subtitle = new TextView();
                this.buttonLayout = new Layout(Api.RelativeLayout);
                this.hide = new Button(theme.hideButtonText);
                this.close = new Button(theme.closeText);

                // Set menu params

                this.params.gravity.value = 51;
                this.params.x.value = theme.menuXPosition;
                this.params.y.value = theme.menuYPosition;

                // Configure self
                this.me.visibility = Api.GONE;
                this.me.backgroundColor = theme.bgColor;
                this.me.orientation = Api.VERTICAL;
                this.me.layoutParams = Layout.LinearLayoutParams(Math.floor(dp(theme.menuWidth)), Api.WRAP_CONTENT);

                // Configure title & subtitle
                const titleParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT); // For `this.title`
                titleParams.addRule(Api.CENTER_HORIZONTAL);

                this.titleLayout.padding = [10, 5, 10, 5];
                this.titleLayout.verticalGravity = 16;
                
                this.title.textColor = theme.primaryTextColor;
                this.title.textSize = 18;
                this.title.gravity = Api.CENTER;
                this.title.layoutParams = titleParams;
                
                this.subtitle.ellipsize = Api.TruncateAt.MARQUEE.value;
                this.subtitle.marqueeRepeatLimit = -1;
                this.subtitle.singleLine = true;
                this.subtitle.selected = true;
                this.subtitle.textColor = theme.primaryTextColor;
                this.subtitle.textSize = 10;
                this.subtitle.gravity = Api.CENTER;
                this.subtitle.padding = [0, 0, 0, 5];

                // Configure proxy & layout
                const proxyParams = Layout.LinearLayoutParams(Api.MATCH_PARENT, Math.floor(dp(theme.menuHeight)));
                this.proxy.layoutParams = proxyParams;
                this.proxy.backgroundColor = theme.layoutColor;
                this.layout.orientation = Api.VERTICAL;

                // Configure hide/kill & close buttons and their layout
                const hideButtonParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
                const closeButtonParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
                this.buttonLayout.padding = [10, 3, 10, 3];
                this.buttonLayout.verticalGravity = Api.CENTER;
                
                hideButtonParams.addRule(Api.ALIGN_PARENT_LEFT);
                this.hide.layoutParams = hideButtonParams;
                this.hide.backgroundColor = Api.TRANSPARENT;
                this.hide.textColor = theme.primaryTextColor;
                this.hide.onClickListener = () => {
                    this.icon.visibility = Api.VISIBLE;
                    this.icon.alpha = 0;
                    this.me.visibility = Api.GONE;
                    toast(theme.iconHiddenText, 1);
                }

                this.hide.onLongClickListener = () => {
                    instance.destroy();
                    toast(theme.killText, 1);
                }

                closeButtonParams.addRule(Api.ALIGN_PARENT_RIGHT);
                this.close.layoutParams = closeButtonParams;
                this.close.backgroundColor = 0;
                this.close.textColor = theme.primaryTextColor;
                this.close.onClickListener = () => {
                    this.icon.visibility = Api.VISIBLE;
                    this.icon.alpha = theme.iconAlpha;
                    this.me.visibility = Api.GONE;
                }
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
        }
    }
}