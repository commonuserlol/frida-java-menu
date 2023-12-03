namespace Menu {
    export class Config {
        /** @internal */
        holder: Map<string, string | number>;

        constructor() {
            this.holder = new Map<string, string>();
        }

        get noOverlayPermission(): string {
            return this.holder.get("noOverlayPermission")! as string;
        }

        set noOverlayPermission(value: string) {
            this.holder.set("noOverlayPermission", value);
        }

        get hide(): string {
            return this.holder.get("hide")! as string;
        }

        set hide(value: string) {
            this.holder.set("hide", value);
        }

        get close(): string {
            return this.holder.get("close")! as string;
        }

        set close(value: string) {
            this.holder.set("close", value);
        }

        get hideCallback(): string {
            return this.holder.get("hideCallback")! as string;
        }

        set hideCallback(value: string) {
            this.holder.set("hideCallback", value);
        }

        get killCallback(): string {
            return this.holder.get("killCallback")! as string;
        }

        set killCallback(value: string) {
            this.holder.set("killCallback", value);
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
        /** Gets buttonOnOff enabled state color */
        get buttonOnOffOnColor(): number {
            return this.holder.get("buttonOnOffOnColor")! as number;
        }
        /** Gets buttonOnOff disabled state color */
        get buttonOnOffOffColor(): number {
            return this.holder.get("buttonOnOffOffColor")! as number;
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
        /** Sets buttonOnOff enabled state color */
        set buttonOnOffOnColor(color: string) {
            this.holder.set("buttonOnOffOnColor", parseColor(color));
        }
        /** Sets buttonOnOff disabled state color */
        set buttonOnOffOffColor(color: string) {
            this.holder.set("buttonOnOffOffColor", parseColor(color));
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
    }
}