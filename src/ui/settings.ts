namespace Menu {
    export class Settings extends Layout {
        settings: TextView;
        state: boolean;
        triggered: boolean;

        constructor(label: string, state: boolean = false) {
            super(Api.LinearLayout);
            this.settings = new TextView(label);
            this.state = state;
            this.triggered = false;

            const settingsParams = Layout.RelativeLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            settingsParams.addRule(Api.ALIGN_PARENT_RIGHT);

            // Initialize label
            this.settings.textColor = config.primaryTextColor;
            this.settings.typeface = Api.Typeface.DEFAULT_BOLD.value;
            this.settings.textSize = 20;
            this.settings.layoutParams = settingsParams;
            this.settings.onClickListener = () => this.handleState();

            if (this.state) this.swapViews(this, Menu.instance.template.layout);
        }

        /** Replaces old view with new one */
        swapViews(_new: View, old: View) {
            const add = Menu.instance.add;
            const remove = Menu.instance.remove;
            const proxy = Menu.instance.template.proxy;
            
            remove(old, proxy);
            add(_new, proxy);
        }

        /** Handler for state change (onClick event) */
        handleState() {
            if (this.visibility == Api.VISIBLE) this.triggered = true;
            if (this.triggered) this.state = !this.state;
            this.state ? this.swapViews(this, Menu.instance.template.layout) : (this.triggered ? this.swapViews(Menu.instance.template.layout, this) : null);
        }
    }
}