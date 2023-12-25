namespace Menu {
    /** Implementation of settings for LGL layout */
    export class Settings extends Layout {
        /** TextView which will toggle state */
        settings: TextView;
        /** @internal Is settings opened? */
        state: boolean;
        /** @internal Workaround to open settings if `state == true` by default */
        triggered: boolean;

        constructor(label: string, state: boolean = false) {
            super(Api.LinearLayout);
            const settingsParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            settingsParams.addRule(Api.ALIGN_PARENT_RIGHT);

            this.settings = new TextView(label);
            this.settings.textColor = config.color.primaryText;
            this.settings.typeface = Api.Typeface.DEFAULT_BOLD.value;
            this.settings.textSize = 20;
            this.settings.layoutParams = settingsParams;
            this.settings.onClickListener = () => this.handleState();

            this.state = state;
            this.triggered = false;

            if (this.state)
                this.swapViews(this, Menu.instance.layout.layout);
        }

        /** @internal Replaces old view with new one */
        swapViews(_new: View, old: View) {
            const proxy = Menu.instance.layout.proxy;
            
            remove(old, proxy);
            add(_new, proxy);
        }

        /** @internal Handler for state change (onClick event) */
        handleState() {
            if (this.visibility == Api.VISIBLE)
                this.triggered = true;
            if (this.triggered)
                this.state = !this.state;
            if (this.state)
                this.swapViews(this, Menu.instance.layout.layout);
            else
                if (this.triggered)
                    this.swapViews(Menu.instance.layout.layout, this);
        }
    }
}