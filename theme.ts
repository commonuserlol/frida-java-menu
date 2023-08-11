namespace Menu {
    export class Theme {
        private holder: Map<string, string | number>;
        
        constructor () {
            this.holder = new Map<string, string | number>();
        }

        /**
         * Gets background color
         *
         * @type {number}
         */
        get bgColor(): number {
            return this.holder.get("bgColor")! as number;
        }
        /**
         * Gets button backdground color
         *
         * @type {number}
         */
        get buttonColor(): number {
            return this.holder.get("buttonColor")! as number;
        }
        /**
         * Gets category background color
         *
         * @type {number}
         */
        get categoryColor(): number {
            return this.holder.get("categoryColor")! as number;
        }
        /**
         * Gets collapse background color
         *
         * @type {number}
         */
        get collapseColor(): number {
            return this.holder.get("collapseColor")! as number;
        }
        /**
         * Gets menu general layout color
         *
         * @type {number}
         */
        get layoutColor(): number {
            return this.holder.get("layoutColor")! as number;
        }
        /**
         * Gets primary text color
         *
         * @type {number}
         */
        get primaryTextColor(): number {
            return this.holder.get("primaryTextColor")! as number;
        }
        /**
         * Gets secondary text color
         *
         * @type {number}
         */
        get secondaryTextColor(): number {
            return this.holder.get("secondaryTextColor")! as number;
        }

        /**
         * Gets menu height
         *
         * @type {number}
         */
        get menuHeight(): number {
            return this.holder.get("menuHeight")! as number;
        }
        /**
         * Gets menu width
         *
         * @type {number}
         */
        get menuWidth(): number {
            return this.holder.get("menuWidth")! as number;
        }
        /**
         * Get menu position by X
         *
         * @type {number}
         */
        get menuXPosition(): number {
            return this.holder.get("menuXPosition")! as number;
        }
        /**
         * Get menu position by Y
         *
         * @type {number}
         */
        get menuYPosition(): number {
            return this.holder.get("menuYPosition")! as number;
        }

        /**
         * Gets icon alpha
         *
         * @type {number}
         */
        get iconAlpha(): number {
            return this.holder.get("iconAlpha")! as number;
        }
        /**
         * Gets icon size
         *
         * @type {number}
         */
        get iconSize(): number {
            return this.holder.get("iconSize")! as number;
        }

        /**
         * Gets no overlay permission string
         *
         * @type {string}
         */
        get noOverlayPermissionText(): string {
            return this.holder.get("noOverlay")! as string;
        }
        /**
         * Gets hide button string
         *
         * @type {string}
         */
        get hideButtonText(): string {
            return this.holder.get("hideButtonText")! as string;
        }
        /**
         * Gets icon hidden string
         *
         * @type {string}
         */
        get iconHiddenText(): string {
            return this.holder.get("iconHiddenText")! as string;
        }
        /**
         * Gets menu killed string
         *
         * @type {string}
         */
        get killText(): string {
            return this.holder.get("killText")! as string;
        }
        /**
         * Gets menu closed string
         *
         * @type {string}
         */
        get closeText(): string {
            return this.holder.get("closeText")! as string;
        }
        /**
         * Gets positive button string in dialog
         *
         * @type {string}
         */
        get dialogPositiveText(): string {
            return this.holder.get("dialogPositiveText")! as string;
        }
        /**
         * Gets negative button string in dialog
         *
         * @type {string}
         */
        get dialogNegativeText(): string {
            return this.holder.get("dialogNegativeText")! as string;
        }

        /**
         * Sets background color
         *
         * @type {number}
         */
        set bgColor(color: string) {
            this.holder.set("bgColor", parseColor(color));
        }
        /**
         * Sets button background color
         *
         * @type {number}
         */
        set buttonColor(color: string) {
            this.holder.set("buttonColor", parseColor(color));
        }
        /**
         * Sets category background color
         *
         * @type {number}
         */
        set categoryColor(color: string) {
            this.holder.set("categoryColor", parseColor(color));
        }
        /**
         * Sets collapse background color
         *
         * @type {number}
         */
        set collapseColor(color: string) {
            this.holder.set("collapseColor", parseColor(color));
        }
        /**
         * Sets menu general layout background color
         *
         * @type {number}
         */
        set layoutColor(color: string) {
            this.holder.set("layoutColor", parseColor(color));
        }
        /**
         * Sets primary text color
         *
         * @type {number}
         */
        set primaryTextColor(color: string) {
            this.holder.set("primaryTextColor", parseColor(color));
        }
        /**
         * Sets secondary text color
         *
         * @type {number}
         */
        set secondaryTextColor(color: string) {
            this.holder.set("secondaryTextColor", parseColor(color));
        }

        /**
         * Sets menu height
         *
         * @type {number}
         */
        set menuHeight(menuHeight: number) {
            this.holder.set("menuHeight", menuHeight);
        }
        /**
         * Sets menu width
         *
         * @type {number}
         */
        set menuWidth(menuWidth: number) {
            this.holder.set("menuWidth", menuWidth);
        }
        /**
         * Sets menu X position
         *
         * @type {number}
         */
        set menuXPosition(menuXPosition: number) {
            this.holder.set("menuXPosition", menuXPosition);
        }
        /**
         * Sets menu Y position
         *
         * @type {number}
         */
        set menuYPosition(menuYPosition: number) {
            this.holder.set("menuYPosition", menuYPosition);
        }

        /**
         * Sets icon alpha
         *
         * @type {number}
         */
        set iconAlpha(iconAlpha: number) {
            this.holder.set("iconAlpha", iconAlpha);
        }
        /**
         * Sets icon size
         *
         * @type {number}
         */
        set iconSize(iconSize: number) {
            this.holder.set("iconSize", iconSize);
        }

        /**
         * Sets no overlay permission string
         *
         * @type {string}
         */
        set noOverlayPermissionText(text: string) {
            this.holder.set("noOverlay", text);
        }
        /**
         * Sets hide button string
         *
         * @type {string}
         */
        set hideButtonText(text: string) {
            this.holder.set("hideButtonText", text);
        }
        /**
         * Sets icon hidden string
         *
         * @type {string}
         */
        set iconHiddenText(text: string) {
            this.holder.set("iconHiddenText", text);
        }
        /**
         * Sets menu killed string
         *
         * @type {string}
         */
        set killText(text: string) {
            this.holder.set("killText", text);
        }
        /**
         * Sets menu closed string
         *
         * @type {string}
         */
        set closeText(text: string) {
            this.holder.set("closeText", text);
        }
        /**
         * Sets positive button string in dialog
         *
         * @type {string}
         */
        set dialogPositiveText(text: string) {
            this.holder.set("dialogPositiveText", text);
        }
        /**
         * Sets negative button string in dialog
         *
         * @type {string}
         */
        set dialogNegativeText(text: string) {
            this.holder.set("dialogNegativeText", text);
        }

        /**
         * Gets default LGL theme
         *
         * @static
         * @readonly
         * @type {Theme}
         */
        static get LGL(): Theme {
            const lglTheme = new Theme();

            lglTheme.primaryTextColor = "#82CAFD";
            lglTheme.secondaryTextColor = "#FFFFFF";
            lglTheme.buttonColor = "#1C262D";
            lglTheme.bgColor = "#EE1C2A35";
            lglTheme.layoutColor = "#DD141C22";
            lglTheme.collapseColor = "#222D38";
            lglTheme.categoryColor = "#2F3D4C";

            lglTheme.menuWidth = 290;
            lglTheme.menuHeight = 210;
            lglTheme.menuXPosition = 50;
            lglTheme.menuYPosition = 100;

            lglTheme.iconSize = 45;
            lglTheme.iconAlpha = 0.7;

            lglTheme.noOverlayPermissionText = "Overlay permission required to show menu";
            lglTheme.hideButtonText = "HIDE/KILL (Hold)";
            lglTheme.iconHiddenText = "Icon hidden. Remember the hidden icon position";
            lglTheme.killText = "Menu killed";
            lglTheme.closeText = "MINIMIZE";
            lglTheme.dialogPositiveText = "OK";
            lglTheme.dialogNegativeText = "Cancel";

            return lglTheme;
        }
    }
}
